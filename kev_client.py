import requests
import sys
import json
import os

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = "kev_cache.json"


def download_kev(force=False):
    if not force and os.path.exists(KEV_CACHE_FILE):
        with open(KEV_CACHE_FILE) as f:
            return json.load(f)

    try:
        print("  Downloading CISA KEV catalogue...")
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        with open(KEV_CACHE_FILE, "w") as f:
            json.dump(data, f)

        print(f"  Downloaded {len(data.get('vulnerabilities', []))} KEV entries.")
        return data

    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Failed to download CISA KEV: {e}")
        return {"vulnerabilities": []}


def check_kev(cve_ids, kev_data=None):
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    if kev_data is None:
        kev_data = download_kev()

    kev_lookup = {v.get("cveID"): v for v in kev_data.get("vulnerabilities", [])}

    matches = {}
    for cve_id in cve_ids:
        if cve_id in kev_lookup:
            e = kev_lookup[cve_id]
            matches[cve_id] = {
                "vendor": e.get("vendorProject"),
                "product": e.get("product"),
                "name": e.get("vulnerabilityName"),
                "description": e.get("shortDescription"),
                "date_added": e.get("dateAdded"),
                "due_date": e.get("dueDate"),
                "ransomware_use": e.get("knownRansomwareCampaignUse"),
                "required_action": e.get("requiredAction")
            }

    return matches


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python kev_client.py <CVE-ID> [CVE-ID ...]")
        sys.exit(1)

    cve_ids = sys.argv[1:]
    print(f"\nChecking {len(cve_ids)} CVE(s) against CISA KEV...\n")
    matches = check_kev(cve_ids)

    if not matches:
        print("  None found in KEV.")
    else:
        print(f"  {len(matches)} match(es):\n")
        for cve_id, e in matches.items():
            print(f"  {cve_id} — {e['name']}")
            print(f"    Vendor: {e['vendor']} / {e['product']}")
            print(f"    Added: {e['date_added']}")
            print(f"    Ransomware: {e['ransomware_use']}")
            print(f"    Action: {e['required_action']}\n")