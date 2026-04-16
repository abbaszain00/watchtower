import os
from datetime import datetime
from google.cloud import bigquery
from dotenv import load_dotenv

load_dotenv()

PROJECT_ID = "watchtower-493408"
DATASET_ID = "watchtower_data"
TABLE_ID = "scan_findings"
FULL_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"

KEY_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "watchtower-493408-3429bdc3bd84.json")


def get_client():
    # Streamlit Cloud first, fall back to local key file
    try:
        import streamlit as st
        if hasattr(st, 'secrets') and "gcp_service_account" in st.secrets:
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_info(dict(st.secrets["gcp_service_account"]))
            return bigquery.Client(credentials=creds, project=PROJECT_ID)
    except ImportError:
        pass
    except Exception as e:
        print(f"  [WARNING] Streamlit secrets failed: {e}")

    if os.path.exists(KEY_FILE):
        return bigquery.Client.from_service_account_json(KEY_FILE, project=PROJECT_ID)

    raise FileNotFoundError(f"No credentials found — need Streamlit secrets or {KEY_FILE}")


def setup_bigquery():
    """Create dataset + table if they don't exist. Run once before first scan."""
    client = get_client()

    dataset_ref = bigquery.DatasetReference(PROJECT_ID, DATASET_ID)
    dataset = bigquery.Dataset(dataset_ref)
    dataset.location = "US"

    try:
        client.get_dataset(dataset_ref)
        print(f"  Dataset {DATASET_ID} already exists.")
    except Exception:
        client.create_dataset(dataset)
        print(f"  Created dataset {DATASET_ID}.")

    schema = [
        bigquery.SchemaField("scan_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("scan_timestamp", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("source_file", "STRING"),
        bigquery.SchemaField("package", "STRING"),
        bigquery.SchemaField("ecosystem", "STRING"),
        bigquery.SchemaField("cve_id", "STRING"),
        bigquery.SchemaField("summary", "STRING"),
        bigquery.SchemaField("cvss_score", "FLOAT64"),
        bigquery.SchemaField("epss_score", "FLOAT64"),
        bigquery.SchemaField("epss_percentile", "FLOAT64"),
        bigquery.SchemaField("in_kev", "BOOLEAN"),
        bigquery.SchemaField("ransomware_use", "STRING"),
        bigquery.SchemaField("priority", "STRING"),
        bigquery.SchemaField("priority_reasoning", "STRING"),
        bigquery.SchemaField("llm_explanation", "STRING"),
        bigquery.SchemaField("triage_time_seconds", "FLOAT64"),
        bigquery.SchemaField("total_findings", "INTEGER"),
    ]

    table_ref = dataset_ref.table(TABLE_ID)
    table = bigquery.Table(table_ref, schema=schema)

    try:
        client.get_table(table_ref)
        print(f"  Table {TABLE_ID} already exists.")
    except Exception:
        client.create_table(table)
        print(f"  Created table {TABLE_ID}.")

    return client


def save_findings(findings, source_file, triage_time, scan_id=None):
    client = get_client()

    if scan_id is None:
        scan_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    timestamp = datetime.utcnow().isoformat()
    rows = []

    for f in findings:
        primary_cve = f["cve_ids"][0] if f.get("cve_ids") else f.get("vuln_id", "")
        rows.append({
            "scan_id": scan_id,
            "scan_timestamp": timestamp,
            "source_file": source_file,
            "package": f.get("package", ""),
            "ecosystem": f.get("ecosystem", ""),
            "cve_id": primary_cve,
            "summary": f.get("summary", ""),
            "cvss_score": f.get("cvss_score"),
            "epss_score": f.get("epss"),
            "epss_percentile": f.get("epss_percentile"),
            "in_kev": f.get("in_kev", False),
            "ransomware_use": f.get("kev_details", {}).get("ransomware_use") if f.get("kev_details") else None,
            "priority": f.get("priority", ""),
            "priority_reasoning": f.get("priority_reasoning", ""),
            "llm_explanation": f.get("llm_explanation"),
            "triage_time_seconds": triage_time,
            "total_findings": len(findings),
        })

    if rows:
        errors = client.insert_rows_json(FULL_TABLE_ID, rows)
        if errors:
            print(f"  [ERROR] BigQuery insert errors: {errors}")
        else:
            print(f"  Saved {len(rows)} findings to BigQuery.")

    return scan_id


def get_latest_scan():
    client = get_client()
    query = f"""
        SELECT *
        FROM `{FULL_TABLE_ID}`
        WHERE scan_id = (
            SELECT scan_id FROM `{FULL_TABLE_ID}`
            ORDER BY scan_timestamp DESC LIMIT 1
        )
        ORDER BY
            CASE priority
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END,
            epss_score DESC
    """
    return [dict(row) for row in client.query(query).result()]


def get_all_scans():
    client = get_client()
    query = f"""
        SELECT
            scan_id,
            MIN(scan_timestamp) as scan_time,
            MIN(source_file) as source_file,
            COUNT(*) as total_findings,
            COUNTIF(priority = 'CRITICAL') as critical_count,
            COUNTIF(priority = 'HIGH') as high_count,
            COUNTIF(priority = 'MEDIUM') as medium_count,
            COUNTIF(priority = 'LOW') as low_count,
            MIN(triage_time_seconds) as triage_time
        FROM `{FULL_TABLE_ID}`
        GROUP BY scan_id
        ORDER BY scan_time DESC
    """
    return [dict(row) for row in client.query(query).result()]


def get_last_scan_packages():
    client = get_client()
    query = f"""
        SELECT DISTINCT package, ecosystem
        FROM `{FULL_TABLE_ID}`
        WHERE scan_id = (
            SELECT scan_id FROM `{FULL_TABLE_ID}`
            ORDER BY scan_timestamp DESC LIMIT 1
        )
    """
    packages = []
    for row in client.query(query).result():
        pkg = dict(row)
        parts = pkg["package"].rsplit(" ", 1)
        if len(parts) == 2:
            packages.append({"name": parts[0], "version": parts[1], "ecosystem": pkg["ecosystem"]})
    return packages


if __name__ == "__main__":
    print("\nSetting up BigQuery...\n")
    setup_bigquery()
    print("\nDone.")