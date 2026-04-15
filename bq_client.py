"""
bq_client.py — BigQuery integration for Watchtower.
Stores scan findings in BigQuery for dashboard consumption.

Requires:
  - pip install google-cloud-bigquery
  - GCP service account JSON key file
  - GOOGLE_APPLICATION_CREDENTIALS env var pointing to the key file
"""

import os
from datetime import datetime
from google.cloud import bigquery
from dotenv import load_dotenv

load_dotenv()

PROJECT_ID = "watchtower-493408"
DATASET_ID = "watchtower_data"
TABLE_ID = "scan_findings"
FULL_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"

# Point to your service account key
KEY_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "watchtower-493408-3429bdc3bd84.json")


def get_client():
    """Create an authenticated BigQuery client."""
    return bigquery.Client.from_service_account_json(KEY_FILE, project=PROJECT_ID)


def setup_bigquery():
    """
    Create the dataset and table if they don't exist.
    Run this once before first scan.
    """
    client = get_client()

    # Create dataset
    dataset_ref = bigquery.DatasetReference(PROJECT_ID, DATASET_ID)
    dataset = bigquery.Dataset(dataset_ref)
    dataset.location = "US"

    try:
        client.get_dataset(dataset_ref)
        print(f"  Dataset {DATASET_ID} already exists.")
    except Exception:
        client.create_dataset(dataset)
        print(f"  Created dataset {DATASET_ID}.")

    # Define table schema
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
    """
    Write scan findings to BigQuery.

    Args:
        findings: list of finding dicts from scan.py
        source_file: name of the scanned file
        triage_time: total scan time in seconds
        scan_id: optional scan identifier (auto-generated if not provided)
    """
    client = get_client()

    if scan_id is None:
        scan_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    timestamp = datetime.utcnow().isoformat()
    total_findings = len(findings)

    rows = []
    for finding in findings:
        primary_cve = finding["cve_ids"][0] if finding.get("cve_ids") else finding.get("vuln_id", "")

        row = {
            "scan_id": scan_id,
            "scan_timestamp": timestamp,
            "source_file": source_file,
            "package": finding.get("package", ""),
            "ecosystem": finding.get("ecosystem", ""),
            "cve_id": primary_cve,
            "summary": finding.get("summary", ""),
            "cvss_score": finding.get("cvss_score"),
            "epss_score": finding.get("epss"),
            "epss_percentile": finding.get("epss_percentile"),
            "in_kev": finding.get("in_kev", False),
            "ransomware_use": finding.get("kev_details", {}).get("ransomware_use") if finding.get("kev_details") else None,
            "priority": finding.get("priority", ""),
            "priority_reasoning": finding.get("priority_reasoning", ""),
            "llm_explanation": finding.get("llm_explanation"),
            "triage_time_seconds": triage_time,
            "total_findings": total_findings,
        }
        rows.append(row)

    if rows:
        errors = client.insert_rows_json(FULL_TABLE_ID, rows)
        if errors:
            print(f"  [ERROR] BigQuery insert errors: {errors}")
        else:
            print(f"  Saved {len(rows)} findings to BigQuery.")

    return scan_id


def get_latest_scan():
    """
    Retrieve the most recent scan results from BigQuery.
    Returns a list of dicts.
    """
    client = get_client()

    query = f"""
        SELECT *
        FROM `{FULL_TABLE_ID}`
        WHERE scan_id = (
            SELECT scan_id
            FROM `{FULL_TABLE_ID}`
            ORDER BY scan_timestamp DESC
            LIMIT 1
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

    results = client.query(query).result()
    return [dict(row) for row in results]


def get_all_scans():
    """
    Retrieve a summary of all scans.
    Returns one row per scan with counts.
    """
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

    results = client.query(query).result()
    return [dict(row) for row in results]


if __name__ == "__main__":
    print("\nSetting up BigQuery for Watchtower...\n")
    setup_bigquery()
    print("\nDone. BigQuery is ready.")