# LLM explanations via OpenRouter — explains findings, never scores them
# Needs OPENROUTER_API_KEY in .env

import requests
import os
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = "mistralai/mistral-small-3.1-24b-instruct"


def explain_vulnerability(vuln_data):
    if not OPENROUTER_API_KEY:
        print("  [ERROR] OPENROUTER_API_KEY not set in .env")
        return None

    epss_str = f"{vuln_data['epss']:.1%}" if vuln_data.get("epss") else "Not available"
    epss_pct_str = f"{vuln_data['epss_percentile']:.1%}" if vuln_data.get("epss_percentile") else "Not available"
    cvss_str = f"{vuln_data['cvss_score']:.1f}" if vuln_data.get("cvss_score") else "Not available"

    kev_section = ""
    if vuln_data.get("in_kev") and vuln_data.get("kev_details"):
        kev = vuln_data["kev_details"]
        kev_section = f"""
- CISA KEV Status: ACTIVELY EXPLOITED
- KEV Name: {kev.get('name', 'N/A')}
- Ransomware Use: {kev.get('ransomware_use', 'Unknown')}
- Required Action: {kev.get('required_action', 'N/A')}"""

    prompt = f"""You are a senior cybersecurity analyst writing a brief for a security manager.

A vulnerability has been detected and scored by our automated triage system. Explain the assessment clearly and concisely.

VULNERABILITY DETAILS:
- Package: {vuln_data['package']}
- CVE: {vuln_data['vuln_id']}
- Description: {vuln_data['summary']}
- Estimated CVSS: {cvss_str}
- EPSS (probability of exploitation in 30 days): {epss_str}
- EPSS Percentile: {epss_pct_str}
- In CISA KEV (confirmed active exploitation): {'YES' if vuln_data.get('in_kev') else 'No'}{kev_section}

ASSIGNED PRIORITY: {vuln_data['priority']}
SCORING RATIONALE: {vuln_data['priority_reasoning']}

Write exactly 3 short paragraphs:

1. WHAT: What this vulnerability is and what it could allow an attacker to do (2 sentences max).
2. WHY THIS PRIORITY: Why it was assigned {vuln_data['priority']} priority, referencing the specific EPSS, CVSS, and KEV data (2 sentences max).
3. ACTION: What the team should do about it — be specific about the package and version (1-2 sentences max).

Be direct and concise. No bullet points. No headers. Just three short paragraphs."""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 400
    }

    try:
        resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] LLM request failed: {e}")
        return None


if __name__ == "__main__":
    test = {
        "package": "Pillow 9.5.0",
        "vuln_id": "CVE-2023-4863",
        "summary": "libwebp: OOB write in BuildHuffmanTable",
        "priority": "CRITICAL",
        "priority_reasoning": "In CISA KEV — active exploitation confirmed",
        "cvss_score": 9.6,
        "epss": 0.936,
        "epss_percentile": 0.998,
        "in_kev": True,
        "kev_details": {
            "name": "Google Chromium WebP Heap-Based Buffer Overflow Vulnerability",
            "ransomware_use": "Unknown",
            "required_action": "Apply mitigations per vendor instructions."
        }
    }

    print("\nTesting LLM explanation...\n")
    result = explain_vulnerability(test)

    if result:
        print(f"  Priority: {test['priority']}")
        print(f"  Scoring: {test['priority_reasoning']}\n")
        for line in result.strip().split("\n"):
            print(f"    {line}")
    else:
        print("  Failed — check OPENROUTER_API_KEY in .env")