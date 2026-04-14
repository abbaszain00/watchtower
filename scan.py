"""
scan.py — Main Watchtower pipeline.
Parses dependencies, queries OSV/EPSS/KEV, and runs LLM assessment.

Usage: python scan.py samples/requirements.txt
"""

import sys
import time
from parse_deps import parse_file
from osv_client import query_osv, extract_cve_ids, summarise_vulns
from epss_client import get_epss_scores, format_epss
from kev_client import download_kev, check_kev
from llm_client import assess_vulnerability


def scan(filepath, use_llm=True):
    """Run the full Watchtower scan pipeline."""

    print("=" * 60)
    print("  WATCHTOWER — Vulnerability Triage Pipeline")
    print("=" * 60)

    # Start MTTR timer
    start_time = time.time()

    # Step 1: Parse dependencies
    print(f"\n[1/5] Parsing dependencies from {filepath}...")
    deps = parse_file(filepath)
    print(f"  Found {len(deps)} dependencies.")

    # Step 2: Download CISA KEV (do this once upfront)
    print("\n[2/5] Loading CISA KEV catalogue...")
    kev_data = download_kev()

    # Step 3: Query OSV for each dependency
    print("\n[3/5] Scanning dependencies against OSV...")
    all_findings = []

    for dep in deps:
        vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
        if vulns:
            cve_ids = extract_cve_ids(vulns)
            summaries = summarise_vulns(vulns)
            print(f"  {dep['name']} {dep['version']} — {len(vulns)} vulnerabilities found")

            for i, vuln_summary in enumerate(summaries):
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

    print(f"\n  Total findings: {len(all_findings)}")

    # Step 4: Enrich with EPSS scores
    print("\n[4/5] Enriching with EPSS and CISA KEV data...")

    # Collect all unique CVE IDs for batch EPSS query
    all_cve_ids = set()
    for f in all_findings:
        all_cve_ids.update(f["cve_ids"])

    # Batch EPSS query
    epss_scores = {}
    if all_cve_ids:
        # EPSS API might have limits on batch size, chunk if needed
        cve_list = list(all_cve_ids)
        chunk_size = 30
        for i in range(0, len(cve_list), chunk_size):
            chunk = cve_list[i:i + chunk_size]
            scores = get_epss_scores(chunk)
            epss_scores.update(scores)

    # Check KEV
    kev_matches = check_kev(list(all_cve_ids), kev_data)

    # Attach EPSS and KEV data to findings
    for finding in all_findings:
        for cve_id in finding["cve_ids"]:
            if cve_id in epss_scores:
                finding["epss"] = epss_scores[cve_id]["epss"]
                finding["epss_percentile"] = epss_scores[cve_id]["percentile"]
            if cve_id in kev_matches:
                finding["in_kev"] = True
                finding["kev_details"] = kev_matches[cve_id]

    # Sort findings: KEV first, then by EPSS score descending
    all_findings.sort(key=lambda f: (
        not f["in_kev"],            # KEV entries first
        -(f["epss"] or 0),          # Then by EPSS descending
    ))

    # Step 5: LLM assessment (optional, for top findings)
    print("\n[5/5] Running LLM risk assessments...")

    # Only assess the top N findings to save API calls and time
    top_n = min(5, len(all_findings))
    assessed_findings = all_findings[:top_n]

    for finding in assessed_findings:
        if use_llm:
            # Pick the first CVE ID for display
            primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]

            severity_str = "Not available"
            if finding["severity"]:
                severity_str = str(finding["severity"])

            llm_input = {
                "package": finding["package"],
                "vuln_id": primary_cve,
                "summary": finding["summary"],
                "severity": severity_str,
                "epss": finding["epss"],
                "epss_percentile": finding["epss_percentile"],
                "in_kev": finding["in_kev"],
                "kev_details": finding["kev_details"],
            }

            assessment = assess_vulnerability(llm_input)
            finding["llm_assessment"] = assessment

    # Stop MTTR timer
    elapsed = time.time() - start_time

    # Print results
    print("\n")
    print("=" * 60)
    print("  SCAN RESULTS")
    print("=" * 60)
    print(f"\n  Dependencies scanned: {len(deps)}")
    print(f"  Vulnerabilities found: {len(all_findings)}")
    print(f"  In CISA KEV (actively exploited): {sum(1 for f in all_findings if f['in_kev'])}")
    print(f"  Time to triage: {elapsed:.1f} seconds")
    print(f"  Estimated manual triage time: ~{len(all_findings) * 5} minutes")
    print(f"  MTTR improvement: ~{((len(all_findings) * 5 * 60) / max(elapsed, 1)):.0f}x faster")

    print("\n" + "-" * 60)
    print("  TOP FINDINGS (ranked by risk)")
    print("-" * 60)

    for i, finding in enumerate(assessed_findings):
        primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]
        print(f"\n  [{i+1}] {finding['package']} — {primary_cve}")
        print(f"  Summary: {finding['summary']}")

        if finding["epss"] is not None:
            print(f"  EPSS: {format_epss(finding['epss'])} probability (percentile: {format_epss(finding['epss_percentile'])})")

        if finding["in_kev"]:
            print(f"  ⚠ CISA KEV: ACTIVELY EXPLOITED — {finding['kev_details'].get('name', '')}")
            if finding["kev_details"].get("ransomware_use") == "Known":
                print(f"  ⚠ KNOWN RANSOMWARE USE")

        if finding.get("llm_assessment"):
            print(f"\n  AI Assessment:")
            for line in finding["llm_assessment"].strip().split("\n"):
                print(f"    {line}")

        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <filepath> [--no-llm]")
        print("  e.g. python scan.py samples/requirements.txt")
        print("  e.g. python scan.py samples/package.json --no-llm")
        sys.exit(1)

    filepath = sys.argv[1]
    use_llm = "--no-llm" not in sys.argv

    if not use_llm:
        print("  (LLM assessment disabled — running data-only scan)")

    scan(filepath, use_llm=use_llm)
