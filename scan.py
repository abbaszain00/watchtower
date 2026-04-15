"""
scan.py — Main Watchtower pipeline.
Parses dependencies, queries OSV/EPSS/KEV, scores with rules-based system,
and uses LLM to explain the top findings.

Usage:
  python scan.py samples/requirements.txt
  python scan.py samples/package.json --no-llm
"""

import sys
import time
from parse_deps import parse_file
from osv_client import query_osv, extract_cve_ids, summarise_vulns
from epss_client import get_epss_scores, format_epss
from kev_client import download_kev, check_kev
from scorer import calculate_priority
from llm_client import explain_vulnerability
from bq_client import save_findings
from discord_alert import send_alerts


def deduplicate_findings(findings):
    """
    Remove duplicate findings for the same CVE.
    Keeps the entry with the most complete data (has summary, has severity).
    """
    seen = {}
    for finding in findings:
        key = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]

        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            if existing["summary"] == "No summary available" and finding["summary"] != "No summary available":
                seen[key] = finding
            elif not existing["severity"] and finding["severity"]:
                seen[key] = finding

    return list(seen.values())


def format_reasoning_bullets(finding):
    """
    Generate concise reasoning bullets for a finding.
    Returns a list of strings.
    """
    bullets = []

    # KEV status
    if finding["in_kev"]:
        kev = finding.get("kev_details", {})
        bullets.append("In CISA KEV — confirmed active exploitation")
        if kev.get("ransomware_use") == "Known":
            bullets.append("Known ransomware campaign use")
    else:
        bullets.append("Not in CISA KEV — not confirmed actively exploited")

    # CVSS
    cvss = finding.get("cvss_score")
    if cvss is not None:
        if cvss >= 9.0:
            label = "critical severity"
        elif cvss >= 7.0:
            label = "high severity"
        elif cvss >= 4.0:
            label = "medium severity"
        else:
            label = "low severity"
        bullets.append(f"CVSS {cvss:.1f} — {label}")
    else:
        bullets.append("CVSS not available")

    # EPSS
    epss = finding.get("epss")
    if epss is not None:
        if epss >= 0.7:
            label = "very high probability of exploitation"
        elif epss >= 0.2:
            label = "elevated probability of exploitation"
        elif epss >= 0.1:
            label = "moderate probability of exploitation"
        else:
            label = "low probability of exploitation"
        bullets.append(f"EPSS {epss:.1%} — {label}")
    else:
        bullets.append("EPSS not available")

    return bullets


def format_decision_line(finding):
    """
    Generate the decision rule line explaining why this priority was assigned.
    """
    priority = finding["priority"]

    if priority == "CRITICAL":
        return "CRITICAL: KEV status confirms active exploitation (FIRST.org guidance)"
    elif priority == "HIGH":
        return "HIGH: Both severity and exploitation probability exceed thresholds"
    elif priority == "MEDIUM":
        if finding.get("epss") is not None and finding["epss"] >= 0.2:
            return "MEDIUM: Exploitation probability elevated but severity below threshold"
        else:
            return "MEDIUM: Severity exceeds threshold but exploitation probability is low"
    else:
        return "LOW: Below both severity and exploitation probability thresholds"


def scan(filepath, use_llm=True):
    """Run the full Watchtower scan pipeline."""

    print("=" * 60)
    print("  WATCHTOWER — Vulnerability Triage Pipeline")
    print("=" * 60)

    start_time = time.time()

    # Step 1: Parse
    print(f"\n[1/6] Parsing dependencies from {filepath}...")
    deps = parse_file(filepath)
    print(f"  Found {len(deps)} dependencies.")

    # Step 2: Load KEV
    print("\n[2/6] Loading CISA KEV catalogue...")
    kev_data = download_kev()

    # Step 3: OSV scan
    print("\n[3/6] Scanning dependencies against OSV...")
    all_findings = []

    for dep in deps:
        vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
        if vulns:
            cve_ids = extract_cve_ids(vulns)
            summaries = summarise_vulns(vulns)
            print(f"  {dep['name']} {dep['version']} — {len(vulns)} vulnerabilities found")

            for vuln_summary in summaries:
                finding = {
                    "package": f"{dep['name']} {dep['version']}",
                    "ecosystem": dep["ecosystem"],
                    "vuln_id": vuln_summary["id"],
                    "cve_ids": [a for a in vuln_summary["aliases"] if a.startswith("CVE-")],
                    "summary": vuln_summary["summary"],
                    "severity": vuln_summary["severity"],
                    "epss": None,
                    "epss_percentile": None,
                    "in_kev": False,
                    "kev_details": None,
                }
                all_findings.append(finding)
        else:
            print(f"  {dep['name']} {dep['version']} — clean")

    if not all_findings:
        print("\n  No vulnerabilities found. Your dependencies look clean!")
        return

    # Step 4: Deduplicate
    print(f"\n[4/6] Deduplicating findings...")
    print(f"  Before: {len(all_findings)} findings")
    all_findings = deduplicate_findings(all_findings)
    print(f"  After:  {len(all_findings)} unique findings")

    # Step 5: Enrich
    print("\n[5/6] Enriching with EPSS and CISA KEV data...")

    all_cve_ids = set()
    for f in all_findings:
        all_cve_ids.update(f["cve_ids"])

    epss_scores = {}
    if all_cve_ids:
        cve_list = list(all_cve_ids)
        chunk_size = 30
        for i in range(0, len(cve_list), chunk_size):
            chunk = cve_list[i:i + chunk_size]
            scores = get_epss_scores(chunk)
            epss_scores.update(scores)

    kev_matches = check_kev(list(all_cve_ids), kev_data)

    for finding in all_findings:
        for cve_id in finding["cve_ids"]:
            if cve_id in epss_scores:
                finding["epss"] = epss_scores[cve_id]["epss"]
                finding["epss_percentile"] = epss_scores[cve_id]["percentile"]
            if cve_id in kev_matches:
                finding["in_kev"] = True
                finding["kev_details"] = kev_matches[cve_id]

    # Score each finding
    for finding in all_findings:
        score_result = calculate_priority(finding)
        finding["priority"] = score_result["priority"]
        finding["priority_rank"] = score_result["priority_rank"]
        finding["cvss_score"] = score_result["cvss_score"]
        finding["priority_reasoning"] = score_result["reasoning"]

    # Sort by priority rank, then EPSS descending
    all_findings.sort(key=lambda f: (
        f["priority_rank"],
        -(f["epss"] or 0),
    ))

    # Step 6: LLM explanations for CRITICAL and HIGH only
    print("\n[6/6] Generating AI explanations for critical findings...")

    critical_high = [f for f in all_findings if f["priority"] in ("CRITICAL", "HIGH")]

    for finding in critical_high:
        if use_llm:
            primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]

            llm_input = {
                "package": finding["package"],
                "vuln_id": primary_cve,
                "summary": finding["summary"],
                "priority": finding["priority"],
                "priority_reasoning": finding["priority_reasoning"],
                "cvss_score": finding["cvss_score"],
                "epss": finding["epss"],
                "epss_percentile": finding["epss_percentile"],
                "in_kev": finding["in_kev"],
                "kev_details": finding["kev_details"],
            }

            explanation = explain_vulnerability(llm_input)
            finding["llm_explanation"] = explanation

    elapsed = time.time() - start_time

    # Send Discord alerts
    send_alerts(all_findings, {
        "filepath": filepath,
        "deps_scanned": len(deps),
        "elapsed": elapsed,
    })

    # Count by priority
    priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        priority_counts[f["priority"]] += 1

    # ==================== OUTPUT ====================

    print("\n")
    print("=" * 60)
    print("  WATCHTOWER — Scan Results")
    print("=" * 60)
    print(f"  Dependencies scanned:  {len(deps)}")
    print(f"  Vulnerabilities found: {len(all_findings)}")
    print()
    print(f"  CRITICAL: {priority_counts['CRITICAL']}    HIGH: {priority_counts['HIGH']}    MEDIUM: {priority_counts['MEDIUM']}    LOW: {priority_counts['LOW']}")
    print()
    print(f"  Time to triage: {elapsed:.1f} seconds")
    manual_mins = len(all_findings) * 5
    print(f"  Manual equivalent: ~{manual_mins // 60} hours {manual_mins % 60} minutes")
    print("=" * 60)

    # CRITICAL and HIGH findings — full detail
    critical_high = [f for f in all_findings if f["priority"] in ("CRITICAL", "HIGH")]
    medium = [f for f in all_findings if f["priority"] == "MEDIUM"]
    low = [f for f in all_findings if f["priority"] == "LOW"]

    if critical_high:
        print(f"\n  CRITICAL / HIGH ({len(critical_high)})")
        print("  " + "-" * 56)

        for finding in critical_high:
            primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]

            print(f"\n  [{finding['priority']}] {finding['package']} — {primary_cve}")
            print(f"  {finding['summary']}")
            print()

            bullets = format_reasoning_bullets(finding)
            for bullet in bullets:
                print(f"    * {bullet}")

            decision = format_decision_line(finding)
            print(f"    → {decision}")

            if finding.get("llm_explanation"):
                print()
                for line in finding["llm_explanation"].strip().split("\n"):
                    if line.strip():
                        print(f"    {line}")

    if medium:
        print(f"\n\n  MEDIUM ({len(medium)})")
        print("  " + "-" * 56)

        for finding in medium:
            primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]

            print(f"\n  [{finding['priority']}] {finding['package']} — {primary_cve}")
            print(f"  {finding['summary']}")
            print()

            bullets = format_reasoning_bullets(finding)
            for bullet in bullets:
                print(f"    * {bullet}")

            decision = format_decision_line(finding)
            print(f"    → {decision}")

    if low:
        print(f"\n\n  LOW ({len(low)})")
        print("  " + "-" * 56)

        for finding in low:
            primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]
            cvss_str = f"CVSS {finding['cvss_score']:.1f}" if finding.get("cvss_score") else "CVSS N/A"
            epss_str = f"EPSS {finding['epss']:.1%}" if finding.get("epss") is not None else "EPSS N/A"
            print(f"  [LOW] {finding['package']} — {primary_cve}")
            print(f"    {finding['summary']} — {cvss_str} | {epss_str}")

    print()

    # Save to BigQuery
    try:
        print("  Saving findings to BigQuery...")
        save_findings(all_findings, filepath, elapsed)
    except Exception as e:
        print(f"  [WARNING] BigQuery save failed: {e}")
        print(f"  (Results still displayed above — BigQuery is optional)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <filepath> [--no-llm]")
        print("  e.g. python scan.py samples/requirements.txt")
        print("  e.g. python scan.py samples/package.json --no-llm")
        sys.exit(1)

    filepath = sys.argv[1]
    use_llm = "--no-llm" not in sys.argv

    if not use_llm:
        print("  (LLM explanations disabled — running data-only scan)")

    scan(filepath, use_llm=use_llm)