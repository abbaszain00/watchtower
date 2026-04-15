"""
discord_alert.py — Discord alerting for Watchtower.
Add DISCORD_WEBHOOK_URL to your .env file.
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


def send_alerts(all_findings, scan_meta=None):
    """
    Loops through findings and sends Discord alerts.
    CRITICAL and HIGH get individual messages.
    MEDIUM and LOW are bundled into one digest.
    Uses the priority already assigned by scorer.py.
    """
    if not WEBHOOK_URL:
        print("  [WARNING] DISCORD_WEBHOOK_URL not set in .env — skipping alerts")
        return

    for finding in all_findings:
        tier = finding.get("priority", "LOW")
        cve = finding["cve_ids"][0] if finding.get("cve_ids") else finding.get("vuln_id", "Unknown")
        epss = finding.get("epss")
        epss_str = f"{epss * 100:.1f}%" if epss is not None else "N/A"
        package = finding.get("package", "Unknown")
        summary = finding.get("summary", "No summary available")
        llm = finding.get("llm_explanation", "") or ""
        kev = finding.get("kev_details") or {}

        if tier == "CRITICAL":
            lines = [
                "@everyone 🚨 CRITICAL vulnerability — act immediately",
                f"**Package:** {package}",
                f"**CVE:** {cve}",
                f"**EPSS:** {epss_str} exploitation probability",
                f"**Summary:** {summary}",
            ]
            if finding.get("in_kev"):
                lines.append(f"**CISA KEV:** {kev.get('name', 'Actively exploited in the wild')}")
            if kev.get("ransomware_use") == "Known":
                lines.append("**Ransomware:** Known ransomware campaign use confirmed")
            if kev.get("required_action"):
                lines.append(f"**Required action:** {kev['required_action']}")
            if llm:
                lines.append(f"**AI assessment:**\n{llm}")
            post_message("\n".join(lines))

        elif tier == "HIGH":
            lines = [
                f"🔴 HIGH severity vulnerability",
                f"**Package:** {package}",
                f"**CVE:** {cve}",
                f"**EPSS:** {epss_str} exploitation probability",
                f"**Summary:** {summary}",
            ]
            if finding.get("in_kev"):
                lines.append(f"**CISA KEV:** {kev.get('name', 'Actively exploited in the wild')}")
            if llm:
                lines.append(f"**AI assessment:**\n{llm}")
            post_message("\n".join(lines))

    # Send a clean scan message if nothing was found
    if not all_findings and scan_meta:
        filepath = scan_meta.get("filepath", "your dependencies")
        deps = scan_meta.get("deps_scanned", "?")
        post_message(f"✅ Clean scan — no vulnerabilities found in `{filepath}` ({deps} packages checked)")


def post_message(text):
    """Send a plain text message to the Discord webhook."""
    if not WEBHOOK_URL:
        return
    try:
        response = requests.post(WEBHOOK_URL, json={"content": text}, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Discord alert failed: {e}")