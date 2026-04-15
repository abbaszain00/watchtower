"""Query the OSV API for known vulnerabilities. https://google.github.io/osv.dev/api/"""

import requests
import sys

OSV_API_URL = "https://api.osv.dev/v1/query"


def query_osv(package_name, version, ecosystem):
    """
    Query OSV for vulnerabilities affecting a specific package version.
    Returns a list of vulnerability objects.
    """
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
        return data.get("vulns", [])
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] OSV query failed for {package_name} {version}: {e}")
        return []


def extract_cve_ids(vulns):
    """Extract CVE IDs from OSV vulnerability objects."""
    cve_ids = set()
    for vuln in vulns:
        # Check the aliases field for CVE IDs
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_ids.add(alias)
        # Also check the ID itself
        if vuln.get("id", "").startswith("CVE-"):
            cve_ids.add(vuln["id"])
    return list(cve_ids)


def summarise_vulns(vulns):
    """Create a simplified summary of each vulnerability."""
    summaries = []
    for vuln in vulns:
        summary = {
            "id": vuln.get("id"),
            "aliases": vuln.get("aliases", []),
            "summary": vuln.get("summary", "No summary available"),
            "details": vuln.get("details", "")[:300],
            "severity": [],
            "references": [ref.get("url") for ref in vuln.get("references", [])[:3]]
        }
        # Extract severity info
        for sev in vuln.get("severity", []):
            summary["severity"].append({
                "type": sev.get("type"),
                "score": sev.get("score")
            })
        summaries.append(summary)
    return summaries


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python osv_client.py <package_name> <version> <ecosystem>")
        print("  e.g. python osv_client.py Django 4.2.0 PyPI")
        print("  e.g. python osv_client.py express 4.17.1 npm")
        sys.exit(1)

    name = sys.argv[1]
    version = sys.argv[2]
    ecosystem = sys.argv[3]

    print(f"\nQuerying OSV for {name} {version} ({ecosystem})...\n")
    vulns = query_osv(name, version, ecosystem)

    if not vulns:
        print("  No vulnerabilities found.")
    else:
        print(f"  Found {len(vulns)} vulnerabilities:\n")
        cve_ids = extract_cve_ids(vulns)
        summaries = summarise_vulns(vulns)

        for s in summaries:
            print(f"  [{s['id']}] {s['summary']}")
            if s["severity"]:
                for sev in s["severity"]:
                    print(f"    Severity: {sev['type']} — {sev['score']}")
            print()

        if cve_ids:
            print(f"  CVE IDs found: {', '.join(cve_ids)}")