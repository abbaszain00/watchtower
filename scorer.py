"""
scorer.py — Watchtower vulnerability scoring system.

Prioritisation logic based on:
- FIRST.org EPSS User Guide (https://www.first.org/epss/user-guide)
- FIRST.org EPSS Model (https://www.first.org/epss/model)
- CISA KEV Catalogue (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- CVE_Prioritizer thresholds (EPSS >= 0.2, CVSS >= 6.0)

Priority levels:
  CRITICAL — In CISA KEV (confirmed active exploitation)
  HIGH     — EPSS >= 0.2 AND CVSS >= 6.0 (likely to be exploited AND severe)
  MEDIUM   — EPSS >= 0.2 OR CVSS >= 6.0 (one risk dimension elevated)
  LOW      — EPSS < 0.2 AND CVSS < 6.0 (low on both dimensions)
"""

import re

# Thresholds based on FIRST.org guidance and industry practice
EPSS_THRESHOLD = 0.2
CVSS_THRESHOLD = 6.0


def extract_cvss_score(severity_data):
    """
    Extract the highest CVSS base score from OSV severity data.
    Handles both CVSS v3.1 and v4.0 vector strings.
    Returns a float score or None if no score found.
    """
    if not severity_data:
        return None

    best_score = None

    for entry in severity_data:
        score_str = entry.get("score", "")

        # Try to extract score from CVSS v3.1 vector
        # Format: CVSS:3.1/AV:N/AC:L/... — we need to calculate from the vector
        # But OSV doesn't always give us a base score directly
        # Look for common patterns

        # CVSS v4.0 vectors don't have a simple base score in the string
        # CVSS v3.1 vectors also need calculation
        # Best approach: use known severity mappings from the vector

        if "CVSS:3" in score_str:
            score = _estimate_cvss3_from_vector(score_str)
            if score and (best_score is None or score > best_score):
                best_score = score
        elif "CVSS:4" in score_str:
            score = _estimate_cvss4_from_vector(score_str)
            if score and (best_score is None or score > best_score):
                best_score = score

    return best_score


def _estimate_cvss3_from_vector(vector):
    """
    Estimate a CVSS v3.x base score from the vector string.
    This is a simplified estimation — not a full CVSS calculator.
    Focuses on the key metrics that most affect the score.
    """
    try:
        metrics = {}
        parts = vector.split("/")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        # Simplified scoring based on impact metrics
        impact_score = 0

        # Confidentiality, Integrity, Availability impact
        for metric in ["C", "I", "A"]:
            val = metrics.get(metric, "N")
            if val == "H":
                impact_score += 3.0
            elif val == "L":
                impact_score += 1.0

        # Attack vector
        av = metrics.get("AV", "N")
        if av == "N":  # Network
            impact_score += 1.0
        elif av == "A":  # Adjacent
            impact_score += 0.5

        # Attack complexity
        ac = metrics.get("AC", "L")
        if ac == "L":  # Low complexity = easier to exploit
            impact_score += 0.5

        # Privileges required
        pr = metrics.get("PR", "N")
        if pr == "N":  # No privileges needed
            impact_score += 0.5

        # Map to 0-10 scale
        score = min(10.0, impact_score)
        return score

    except Exception:
        return None


def _estimate_cvss4_from_vector(vector):
    """
    Estimate a CVSS v4.0 base score from the vector string.
    Simplified estimation using impact metrics.
    """
    try:
        metrics = {}
        parts = vector.split("/")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        impact_score = 0

        # CVSS v4 uses VC, VI, VA for vulnerable system impact
        for metric in ["VC", "VI", "VA"]:
            val = metrics.get(metric, "N")
            if val == "H":
                impact_score += 3.0
            elif val == "L":
                impact_score += 1.0

        # Attack vector
        av = metrics.get("AV", "N")
        if av == "N":
            impact_score += 1.0
        elif av == "A":
            impact_score += 0.5

        # Attack complexity
        ac = metrics.get("AC", "L")
        if ac == "L":
            impact_score += 0.5

        # Privileges required
        pr = metrics.get("PR", "N")
        if pr == "N":
            impact_score += 0.5

        score = min(10.0, impact_score)
        return score

    except Exception:
        return None


def calculate_priority(finding):
    """
    Calculate the priority level for a vulnerability finding.

    Args:
        finding: dict with keys:
            - in_kev: bool
            - epss: float or None (0-1 probability)
            - severity: list of severity dicts from OSV

    Returns:
        dict with:
            - priority: str (CRITICAL, HIGH, MEDIUM, LOW)
            - priority_rank: int (1-4, for sorting)
            - cvss_score: float or None
            - reasoning: str (human-readable explanation of why this priority)
    """
    in_kev = finding.get("in_kev", False)
    epss = finding.get("epss")
    severity = finding.get("severity", [])

    cvss_score = extract_cvss_score(severity)

    # Priority 1: CRITICAL — In CISA KEV
    if in_kev:
        reasoning = "CRITICAL: This vulnerability is in the CISA Known Exploited Vulnerabilities catalogue, confirming it is actively being exploited in the wild. Per FIRST.org guidance, confirmed exploitation evidence supersedes all other scoring."
        if epss is not None:
            reasoning += f" EPSS score of {epss:.1%} further supports this assessment."
        return {
            "priority": "CRITICAL",
            "priority_rank": 1,
            "cvss_score": cvss_score,
            "reasoning": reasoning
        }

    # For remaining priorities, we need both EPSS and CVSS
    has_high_epss = epss is not None and epss >= EPSS_THRESHOLD
    has_high_cvss = cvss_score is not None and cvss_score >= CVSS_THRESHOLD

    # Priority 2: HIGH — High EPSS AND high CVSS
    if has_high_epss and has_high_cvss:
        reasoning = f"HIGH: This vulnerability has both a high exploitation probability (EPSS: {epss:.1%}) and high severity (estimated CVSS: {cvss_score:.1f}). Both thresholds exceeded (EPSS >= {EPSS_THRESHOLD:.0%}, CVSS >= {CVSS_THRESHOLD})."
        return {
            "priority": "HIGH",
            "priority_rank": 2,
            "cvss_score": cvss_score,
            "reasoning": reasoning
        }

    # Priority 3: MEDIUM — High EPSS OR high CVSS (but not both)
    if has_high_epss or has_high_cvss:
        if has_high_epss:
            reasoning = f"MEDIUM: Exploitation probability is elevated (EPSS: {epss:.1%}, above {EPSS_THRESHOLD:.0%} threshold) but severity is {'not available' if cvss_score is None else f'lower (estimated CVSS: {cvss_score:.1f}, below {CVSS_THRESHOLD} threshold)'}."
        else:
            reasoning = f"MEDIUM: Severity is elevated (estimated CVSS: {cvss_score:.1f}, above {CVSS_THRESHOLD} threshold) but exploitation probability is {'not available' if epss is None else f'lower (EPSS: {epss:.1%}, below {EPSS_THRESHOLD:.0%} threshold)'}."
        return {
            "priority": "MEDIUM",
            "priority_rank": 3,
            "cvss_score": cvss_score,
            "reasoning": reasoning
        }

    # Priority 4: LOW — Below both thresholds
    epss_str = f"{epss:.1%}" if epss is not None else "not available"
    cvss_str = f"{cvss_score:.1f}" if cvss_score is not None else "not available"
    reasoning = f"LOW: Both exploitation probability (EPSS: {epss_str}) and severity (estimated CVSS: {cvss_str}) are below thresholds (EPSS < {EPSS_THRESHOLD:.0%}, CVSS < {CVSS_THRESHOLD})."

    return {
        "priority": "LOW",
        "priority_rank": 4,
        "cvss_score": cvss_score,
        "reasoning": reasoning
    }


if __name__ == "__main__":
    # Test with sample findings
    test_cases = [
        {
            "name": "In CISA KEV (actively exploited)",
            "in_kev": True,
            "epss": 0.936,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        },
        {
            "name": "High EPSS + High CVSS",
            "in_kev": False,
            "epss": 0.45,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}]
        },
        {
            "name": "High CVSS but low EPSS",
            "in_kev": False,
            "epss": 0.05,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        },
        {
            "name": "High EPSS but low CVSS",
            "in_kev": False,
            "epss": 0.35,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]
        },
        {
            "name": "Low on both dimensions",
            "in_kev": False,
            "epss": 0.02,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]
        },
    ]

    print("Watchtower Scoring System Test\n")
    print(f"Thresholds: EPSS >= {EPSS_THRESHOLD:.0%}, CVSS >= {CVSS_THRESHOLD}\n")

    for test in test_cases:
        result = calculate_priority(test)
        print(f"  [{result['priority']}] {test['name']}")
        print(f"    CVSS: {result['cvss_score']}, EPSS: {test.get('epss')}, KEV: {test.get('in_kev')}")
        print(f"    {result['reasoning']}")
        print()