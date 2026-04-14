"""
llm_client.py — Send vulnerability data to an LLM via OpenRouter for risk assessment.
Requires OPENROUTER_API_KEY in .env
"""

import requests
import os
import sys
import json
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = "mistralai/mistral-small-3.1-24b-instruct"  # Cheap, capable, Mistral as per brief


def assess_vulnerability(vuln_data):
    """
    Send vulnerability data to the LLM and get a risk assessment.

    vuln_data should be a dict with:
        - package: str (e.g. "Django 4.2.0")
        - vuln_id: str (e.g. "CVE-2024-53907")
        - summary: str (vulnerability description)
        - severity: str (CVSS score/vector if available)
        - epss: float or None (exploitation probability)
        - epss_percentile: float or None
        - in_kev: bool (is it in CISA KEV?)
        - kev_details: dict or None
    """
    if not OPENROUTER_API_KEY:
        print("  [ERROR] OPENROUTER_API_KEY not set in .env")
        return None

    prompt = f"""You are a senior cybersecurity analyst. Assess the following vulnerability and provide a risk assessment.

VULNERABILITY:
- Package: {vuln_data['package']}
- ID: {vuln_data['vuln_id']}
- Summary: {vuln_data['summary']}
- Severity: {vuln_data.get('severity', 'Not available')}
- EPSS Score: {vuln_data.get('epss', 'Not available')} (probability of exploitation in next 30 days)
- EPSS Percentile: {vuln_data.get('epss_percentile', 'Not available')}
- In CISA KEV (actively exploited): {'YES' if vuln_data.get('in_kev') else 'No'}
{f"- KEV Details: {json.dumps(vuln_data['kev_details'])}" if vuln_data.get('kev_details') else ''}

Provide your assessment in this exact format:

RISK LEVEL: [CRITICAL / HIGH / MEDIUM / LOW]
EXPLOITATION LIKELIHOOD: [Brief assessment based on EPSS and KEV data]
IMPACT: [What could happen if exploited]
REASONING: [2-3 sentences explaining why you assigned this risk level, referencing the specific data points]
RECOMMENDED ACTION: [Specific remediation step]
"""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0,
        "max_tokens": 500
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] LLM request failed: {e}")
        return None


if __name__ == "__main__":
    # Quick test with a sample vulnerability
    test_data = {
        "package": "Django 4.2.0",
        "vuln_id": "CVE-2024-53907",
        "summary": "Potential denial-of-service vulnerability in strip_tags()",
        "severity": "CVSS:3.1 — 7.5 HIGH",
        "epss": 0.034,
        "epss_percentile": 0.89,
        "in_kev": False,
        "kev_details": None
    }

    print("\nTesting LLM risk assessment...\n")
    result = assess_vulnerability(test_data)

    if result:
        print(result)
    else:
        print("  Failed to get assessment. Check your OPENROUTER_API_KEY in .env")
