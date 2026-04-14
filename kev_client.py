"""
kev_client.py — Download and query the CISA Known Exploited Vulnerabilities (KEV) catalogue.
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Free, no key needed, no rate limits. Just a JSON file download.
"""

import requests
import sys
import json
import os

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = "kev_cache.json"


def download_kev(force=False):
    """
    Download the CISA KEV catalogue.
    Caches locally to avoid re-downloading every run.
    """
    if not force and os.path.exists(KEV_CACHE_FILE):
        with open(KEV_CACHE_FILE, "r") as f:
            return json.load(f)

    try:
        print("  Downloading CISA KEV catalogue...")
        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Cache it
        with open(KEV_CACHE_FILE, "w") as f:
            json.dump(data, f)

        vuln_count = len(data.get("vulnerabilities", []))
        print(f"  Downloaded {vuln_count} KEV entries.")
        return data

    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Failed to download CISA KEV: {e}")
        return {"vulnerabilities": []}


def check_kev(cve_ids, kev_data=None):
    """
    Check which CVE IDs appear in the CISA KEV catalogue.
    Returns a dict mapping CVE ID -> KEV entry for matches.
    """
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    if kev_data is None:
        kev_data = download_kev()

    # Build a lookup dict from the KEV data
    kev_lookup = {}
    for vuln in kev_data.get("vulnerabilities", []):
        kev_lookup[vuln.get("cveID")] = vuln

    # Check each CVE
    matches = {}
    for cve_id in cve_ids:
        if cve_id in kev_lookup:
            entry = kev_lookup[cve_id]
            matches[cve_id] = {
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "name": entry.get("vulnerabilityName"),
                "description": entry.get("shortDescription"),
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "ransomware_use": entry.get("knownRansomwareCampaignUse"),
                "required_action": entry.get("requiredAction")
            }

    return matches


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python kev_client.py <CVE-ID> [CVE-ID ...]")
        print("  e.g. python kev_client.py CVE-2024-53907")
        print("  e.g. python kev_client.py CVE-2023-34362 CVE-2024-42005")
        sys.exit(1)

    cve_ids = sys.argv[1:]

    print(f"\nChecking {len(cve_ids)} CVE(s) against CISA KEV...\n")
    matches = check_kev(cve_ids)

    if not matches:
        print("  None of the provided CVEs are in the CISA KEV catalogue.")
    else:
        print(f"  {len(matches)} CVE(s) found in CISA KEV:\n")
        for cve_id, entry in matches.items():
            print(f"  {cve_id} — {entry['name']}")
            print(f"    Vendor: {entry['vendor']}")
            print(f"    Product: {entry['product']}")
            print(f"    Added to KEV: {entry['date_added']}")
            print(f"    Ransomware use: {entry['ransomware_use']}")
            print(f"    Required action: {entry['required_action']}")
            print()
