import sys
import time
from parse_deps import parse_file
from kev_client import download_kev
from bq_client import save_findings
from discord_alert import send_alerts
from pipeline import deduplicate, scan_deps, enrich, score_and_sort, add_llm_explanations, get_primary_cve


def reasoning_bullets(finding):
    bullets = []

    if finding["in_kev"]:
        bullets.append("In CISA KEV — confirmed active exploitation")
        kev = finding.get("kev_details") or {}
        if kev.get("ransomware_use") == "Known":
            bullets.append("Known ransomware campaign use")
    else:
        bullets.append("Not in CISA KEV")

    cvss = finding.get("cvss_score")
    if cvss is not None:
        label = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        bullets.append(f"CVSS {cvss:.1f} ({label})")
    else:
        bullets.append("CVSS N/A")

    epss = finding.get("epss")
    if epss is not None:
        label = "very high" if epss >= 0.7 else "elevated" if epss >= 0.2 else "moderate" if epss >= 0.1 else "low"
        bullets.append(f"EPSS {epss:.1%} ({label})")
    else:
        bullets.append("EPSS N/A")

    return bullets


def print_finding(finding, verbose=False):
    cve = get_primary_cve(finding)
    print(f"\n  [{finding['priority']}] {finding['package']} — {cve}")
    print(f"  {finding['summary']}")

    if verbose:
        print()
        for bullet in reasoning_bullets(finding):
            print(f"    * {bullet}")
        print(f"    → {finding['priority_reasoning']}")

        llm = finding.get("llm_explanation")
        if llm:
            print()
            for line in llm.strip().split("\n"):
                if line.strip():
                    print(f"    {line}")
    else:
        cvss = finding.get("cvss_score")
        epss = finding.get("epss")
        cvss_str = f"CVSS {cvss:.1f}" if cvss else "CVSS N/A"
        epss_str = f"EPSS {epss:.1%}" if epss is not None else "EPSS N/A"
        print(f"    {cvss_str} | {epss_str}")


def scan(filepath, use_llm=True):
    print(f"\n{'=' * 50}")
    print("  WATCHTOWER — Scan")
    print(f"{'=' * 50}")

    start = time.time()

    print(f"\n[1/6] Parsing {filepath}...")
    deps = parse_file(filepath)
    print(f"  {len(deps)} dependencies")

    print("\n[2/6] Loading CISA KEV catalogue...")
    kev_data = download_kev()

    print("\n[3/6] Scanning against OSV...")
    all_findings = scan_deps(deps)
    for dep in deps:
        has_vulns = any(f["package"].startswith(dep["name"]) for f in all_findings)
        if has_vulns:
            count = sum(1 for f in all_findings if f["package"] == f"{dep['name']} {dep['version']}")
            print(f"  {dep['name']} {dep['version']} — {count} vulns")
        else:
            print(f"  {dep['name']} {dep['version']} — clean")

    if not all_findings:
        print("\n  No vulnerabilities found.")
        return

    print(f"\n[4/6] Deduplicating ({len(all_findings)} raw)...")
    all_findings = deduplicate(all_findings)
    print(f"  {len(all_findings)} unique")

    print("\n[5/6] Enriching with EPSS and KEV...")
    all_findings = enrich(all_findings, kev_data)
    all_findings = score_and_sort(all_findings)

    print("\n[6/6] Generating AI explanations...")
    if use_llm:
        all_findings = add_llm_explanations(all_findings)

    elapsed = time.time() - start

    send_alerts(all_findings, {"filepath": filepath, "deps_scanned": len(deps), "elapsed": elapsed})

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["priority"]] += 1

    print(f"\n{'=' * 50}")
    print(f"  Scan Results — {len(deps)} deps, {len(all_findings)} vulns")
    print(f"  CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}")
    print(f"  Triage time: {elapsed:.1f}s")
    print(f"{'=' * 50}")

    critical_high = [f for f in all_findings if f["priority"] in ("CRITICAL", "HIGH")]
    medium = [f for f in all_findings if f["priority"] == "MEDIUM"]
    low = [f for f in all_findings if f["priority"] == "LOW"]

    if critical_high:
        print(f"\n  CRITICAL / HIGH ({len(critical_high)})")
        print("  " + "-" * 46)
        for f in critical_high:
            print_finding(f, verbose=True)

    if medium:
        print(f"\n\n  MEDIUM ({len(medium)})")
        print("  " + "-" * 46)
        for f in medium:
            print_finding(f, verbose=True)

    if low:
        print(f"\n\n  LOW ({len(low)})")
        print("  " + "-" * 46)
        for f in low:
            print_finding(f, verbose=False)

    print()

    try:
        print("  Saving to BigQuery...")
        save_findings(all_findings, filepath, elapsed)
    except Exception as e:
        print(f"  [WARNING] BigQuery save failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <filepath> [--no-llm]")
        sys.exit(1)

    filepath = sys.argv[1]
    use_llm = "--no-llm" not in sys.argv

    if not use_llm:
        print("  (LLM explanations disabled)")

    scan(filepath, use_llm=use_llm)