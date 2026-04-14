"""
epss_client.py — Query the EPSS API for exploit prediction scores.
API docs: https://www.first.org/epss/api
Free, no key needed.
"""

import requests
import sys

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def get_epss_scores(cve_ids):
    """
    Query EPSS for one or more CVE IDs.
    Accepts a single CVE string or a list of CVEs.
    Returns a dict mapping CVE ID -> {epss, percentile}.
    """
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    if not cve_ids:
        return {}

    # EPSS supports batch queries with comma-separated CVEs
    params = {
        "cve": ",".join(cve_ids)
    }

    try:
        response = requests.get(EPSS_API_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        results = {}
        for entry in data.get("data", []):
            results[entry["cve"]] = {
                "epss": float(entry["epss"]),
                "percentile": float(entry["percentile"])
            }
        return results

    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] EPSS query failed: {e}")
        return {}


def format_epss(score):
    """Format an EPSS score as a readable percentage."""
    return f"{score * 100:.1f}%"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python epss_client.py <CVE-ID> [CVE-ID ...]")
        print("  e.g. python epss_client.py CVE-2024-53907")
        print("  e.g. python epss_client.py CVE-2024-53907 CVE-2024-53908 CVE-2024-42005")
        sys.exit(1)

    cve_ids = sys.argv[1:]

    print(f"\nQuerying EPSS for {len(cve_ids)} CVE(s)...\n")
    scores = get_epss_scores(cve_ids)

    if not scores:
        print("  No EPSS scores found.")
    else:
        for cve_id, data in scores.items():
            probability = format_epss(data["epss"])
            percentile = format_epss(data["percentile"])
            print(f"  {cve_id}")
            print(f"    Exploitation probability (next 30 days): {probability}")
            print(f"    Percentile: {percentile}")
            print()
