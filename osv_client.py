import requests
import sys

OSV_API_URL = "https://api.osv.dev/v1/query"


def query_osv(package_name, version, ecosystem):
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem}
    }
    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] OSV query failed for {package_name} {version}: {e}")
        return []


def extract_cve_ids(vulns):
    cve_ids = set()
    for vuln in vulns:
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_ids.add(alias)
        if vuln.get("id", "").startswith("CVE-"):
            cve_ids.add(vuln["id"])
    return list(cve_ids)


def summarise_vulns(vulns):
    summaries = []
    for vuln in vulns:
        summaries.append({
            "id": vuln.get("id"),
            "aliases": vuln.get("aliases", []),
            "summary": vuln.get("summary", "No summary available"),
            "details": vuln.get("details", "")[:300],
            "severity": [
                {"type": s.get("type"), "score": s.get("score")}
                for s in vuln.get("severity", [])
            ],
            "references": [r.get("url") for r in vuln.get("references", [])[:3]]
        })
    return summaries


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python osv_client.py <package> <version> <ecosystem>")
        sys.exit(1)

    name, version, ecosystem = sys.argv[1], sys.argv[2], sys.argv[3]
    print(f"\nQuerying OSV for {name} {version} ({ecosystem})...\n")

    vulns = query_osv(name, version, ecosystem)
    if not vulns:
        print("  No vulnerabilities found.")
    else:
        print(f"  Found {len(vulns)} vulnerabilities:\n")
        for s in summarise_vulns(vulns):
            print(f"  [{s['id']}] {s['summary']}")
            for sev in s["severity"]:
                print(f"    Severity: {sev['type']} — {sev['score']}")
            print()

        cves = extract_cve_ids(vulns)
        if cves:
            print(f"  CVEs: {', '.join(cves)}")