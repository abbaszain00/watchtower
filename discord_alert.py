"""
discord_alert.py — Discord alerting for Watchtower.
Add DISCORD_WEBHOOK_URL to your .env file.
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


def classify_finding(finding):
    """
    Returns 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW' for a single finding.
    """
    in_kev = finding.get("in_kev", False)
    epss = finding.get("epss") or 0.0
    kev = finding.get("kev_details") or {}
    ransomware = kev.get("ransomware_use", "") == "Known"

    # Pull risk level out of the LLM assessment text
    llm_risk = None
    llm_text = finding.get("llm_assessment", "") or ""
    for line in llm_text.splitlines():
        if line.upper().startswith("RISK LEVEL"):
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if level in line.upper():
                    llm_risk = level
                    break

    if (in_kev and ransomware) or epss > 0.50:
        return "CRITICAL"
    if in_kev or epss > 0.10 or llm_risk in ("CRITICAL", "HIGH"):
        return "HIGH"
    if llm_risk == "MEDIUM" or epss > 0.01:
        return "MEDIUM"
    return "LOW"


def send_alerts(all_findings, scan_meta=None):
    """
    Loops through findings, classifies each one, and sends the right message.
    MEDIUM and LOW findings are bundled into one digest at the end.
    """
    if not WEBHOOK_URL:
        print("  [ERROR] DISCORD_WEBHOOK_URL not set in .env")
        return

    digest_lines = []

    for finding in all_findings:
        tier = classify_finding(finding)
        cve = finding["cve_ids"][0] if finding.get("cve_ids") else finding.get("vuln_id", "Unknown")
        epss = finding.get("epss")
        epss_str = f"{epss * 100:.1f}%" if epss is not None else "N/A"
        package = finding.get("package", "Unknown")
        summary = finding.get("summary", "No summary available")
        llm = finding.get("llm_assessment", "") or ""
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

        else:
            icon = "🟡" if tier == "MEDIUM" else "🟢"
            digest_lines.append(f"{icon} {cve} — {package} (EPSS: {epss_str})")

    # Send one message for all medium/low findings
    if digest_lines:
        digest = "📋 **Lower priority findings — review when you can:**\n" + "\n".join(digest_lines)
        post_message(digest)

    # Send a clean scan message if nothing was found at all
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