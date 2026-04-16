import requests
import sys

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def get_epss_scores(cve_ids):
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    if not cve_ids:
        return {}

    try:
        resp = requests.get(EPSS_API_URL, params={"cve": ",".join(cve_ids)}, timeout=15)
        resp.raise_for_status()
        return {
            e["cve"]: {"epss": float(e["epss"]), "percentile": float(e["percentile"])}
            for e in resp.json().get("data", [])
        }
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] EPSS query failed: {e}")
        return {}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python epss_client.py <CVE-ID> [CVE-ID ...]")
        sys.exit(1)

    scores = get_epss_scores(sys.argv[1:])
    if not scores:
        print("  No scores found.")
    else:
        for cve_id, data in scores.items():
            print(f"  {cve_id}")
            print(f"    Exploitation probability (30d): {data['epss'] * 100:.1f}%")
            print(f"    Percentile: {data['percentile'] * 100:.1f}%\n")