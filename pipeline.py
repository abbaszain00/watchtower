# Shared pipeline logic — used by scan.py and app.py

from osv_client import query_osv, summarise_vulns
from epss_client import get_epss_scores
from kev_client import download_kev, check_kev
from scorer import calculate_priority
from llm_client import explain_vulnerability


def build_finding(dep, vuln_summary):
    return {
        "package": f"{dep['name']} {dep['version']}",
        "ecosystem": dep["ecosystem"],
        "vuln_id": vuln_summary["id"],
        "cve_ids": [a for a in vuln_summary["aliases"] if a.startswith("CVE-")],
        "summary": vuln_summary["summary"],
        "severity": vuln_summary["severity"],
        "epss": None, "epss_percentile": None,
        "in_kev": False, "kev_details": None,
    }


def deduplicate(findings):
    # Keep the most complete entry per CVE
    seen = {}
    for f in findings:
        key = f["cve_ids"][0] if f["cve_ids"] else f["vuln_id"]
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            if existing["summary"] == "No summary available" and f["summary"] != "No summary available":
                seen[key] = f
            elif not existing["severity"] and f["severity"]:
                seen[key] = f
    return list(seen.values())


def get_primary_cve(finding):
    return finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]


def scan_deps(deps, on_progress=None):
    findings = []
    for i, dep in enumerate(deps):
        if on_progress:
            on_progress(i, dep)
        vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
        if vulns:
            for v in summarise_vulns(vulns):
                findings.append(build_finding(dep, v))
    return findings


def enrich(findings, kev_data):
    all_cves = set()
    for f in findings:
        all_cves.update(f["cve_ids"])

    epss_scores = {}
    if all_cves:
        cve_list = list(all_cves)
        for i in range(0, len(cve_list), 30):
            scores = get_epss_scores(cve_list[i:i + 30])
            epss_scores.update(scores)

    kev_matches = check_kev(list(all_cves), kev_data)

    for f in findings:
        for cve_id in f["cve_ids"]:
            if cve_id in epss_scores:
                f["epss"] = epss_scores[cve_id]["epss"]
                f["epss_percentile"] = epss_scores[cve_id]["percentile"]
            if cve_id in kev_matches:
                f["in_kev"] = True
                f["kev_details"] = kev_matches[cve_id]

    return findings


def score_and_sort(findings):
    for f in findings:
        result = calculate_priority(f)
        f["priority"] = result["priority"]
        f["priority_rank"] = result["priority_rank"]
        f["cvss_score"] = result["cvss_score"]
        f["priority_reasoning"] = result["reasoning"]

    findings.sort(key=lambda f: (f["priority_rank"], -(f["epss"] or 0)))
    return findings


def add_llm_explanations(findings):
    for f in findings:
        if f["priority"] not in ("CRITICAL", "HIGH"):
            continue
        f["llm_explanation"] = explain_vulnerability({
            "package": f["package"],
            "vuln_id": get_primary_cve(f),
            "summary": f["summary"],
            "priority": f["priority"],
            "priority_reasoning": f["priority_reasoning"],
            "cvss_score": f["cvss_score"],
            "epss": f["epss"],
            "epss_percentile": f["epss_percentile"],
            "in_kev": f["in_kev"],
            "kev_details": f["kev_details"],
        })
    return findings