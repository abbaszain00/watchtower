"""
Watchtower priority scoring.

Priority levels (based on FIRST.org EPSS User Guide + CVE_Prioritizer thresholds):
  CRITICAL — In CISA KEV (confirmed active exploitation)
  HIGH     — EPSS >= 0.2 AND CVSS >= 6.0
  MEDIUM   — EPSS >= 0.2 OR CVSS >= 6.0 (one dimension elevated)
  LOW      — Below both thresholds
"""

EPSS_THRESHOLD = 0.2
CVSS_THRESHOLD = 6.0


def extract_cvss_score(severity_data):
    """Extract the highest CVSS base score from OSV severity data."""
    if not severity_data:
        return None

    best = None
    for entry in severity_data:
        vector = entry.get("score", "")
        score = _estimate_cvss_from_vector(vector)
        if score and (best is None or score > best):
            best = score
    return best


def _estimate_cvss_from_vector(vector):
    """Rough CVSS estimate from a v3.x or v4.0 vector string. Not a full calculator."""
    if "CVSS:3" not in vector and "CVSS:4" not in vector:
        return None

    try:
        metrics = {}
        for part in vector.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        score = 0

        # Impact metrics — v4 uses VC/VI/VA, v3 uses C/I/A
        if "CVSS:4" in vector:
            impact_keys = ["VC", "VI", "VA"]
        else:
            impact_keys = ["C", "I", "A"]

        for key in impact_keys:
            val = metrics.get(key, "N")
            if val == "H":
                score += 3.0
            elif val == "L":
                score += 1.0

        # Attack vector
        if metrics.get("AV") == "N":
            score += 1.0
        elif metrics.get("AV") == "A":
            score += 0.5

        # Low complexity = easier to exploit
        if metrics.get("AC") == "L":
            score += 0.5

        # No privileges needed
        if metrics.get("PR") == "N":
            score += 0.5

        return min(10.0, score)

    except Exception:
        return None


def calculate_priority(finding):
    """Score a finding and return priority, rank, cvss_score, and reasoning."""
    in_kev = finding.get("in_kev", False)
    epss = finding.get("epss")
    cvss_score = extract_cvss_score(finding.get("severity", []))

    if in_kev:
        reasoning = "In CISA KEV — active exploitation confirmed"
        if epss is not None:
            reasoning += f" (EPSS {epss:.1%})"
        return {"priority": "CRITICAL", "priority_rank": 1, "cvss_score": cvss_score, "reasoning": reasoning}

    high_epss = epss is not None and epss >= EPSS_THRESHOLD
    high_cvss = cvss_score is not None and cvss_score >= CVSS_THRESHOLD

    if high_epss and high_cvss:
        reasoning = f"EPSS {epss:.1%} and CVSS {cvss_score:.1f} both exceed thresholds"
        return {"priority": "HIGH", "priority_rank": 2, "cvss_score": cvss_score, "reasoning": reasoning}

    if high_epss or high_cvss:
        if high_epss:
            cvss_part = "N/A" if cvss_score is None else f"{cvss_score:.1f}"
            reasoning = f"EPSS {epss:.1%} elevated, CVSS {cvss_part} below threshold"
        else:
            epss_part = "N/A" if epss is None else f"{epss:.1%}"
            reasoning = f"CVSS {cvss_score:.1f} elevated, EPSS {epss_part} below threshold"
        return {"priority": "MEDIUM", "priority_rank": 3, "cvss_score": cvss_score, "reasoning": reasoning}

    epss_str = f"{epss:.1%}" if epss is not None else "N/A"
    cvss_str = f"{cvss_score:.1f}" if cvss_score is not None else "N/A"
    reasoning = f"EPSS {epss_str} and CVSS {cvss_str} both below thresholds"
    return {"priority": "LOW", "priority_rank": 4, "cvss_score": cvss_score, "reasoning": reasoning}


if __name__ == "__main__":
    test_cases = [
        {
            "name": "In CISA KEV (actively exploited)",
            "in_kev": True, "epss": 0.936,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        },
        {
            "name": "High EPSS + High CVSS",
            "in_kev": False, "epss": 0.45,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}]
        },
        {
            "name": "High CVSS but low EPSS",
            "in_kev": False, "epss": 0.05,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        },
        {
            "name": "High EPSS but low CVSS",
            "in_kev": False, "epss": 0.35,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]
        },
        {
            "name": "Low on both dimensions",
            "in_kev": False, "epss": 0.02,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]
        },
    ]

    print(f"Watchtower Scoring — Thresholds: EPSS >= {EPSS_THRESHOLD:.0%}, CVSS >= {CVSS_THRESHOLD}\n")

    for test in test_cases:
        result = calculate_priority(test)
        print(f"  [{result['priority']}] {test['name']}")
        print(f"    CVSS: {result['cvss_score']}, EPSS: {test.get('epss')}, KEV: {test.get('in_kev')}")
        print(f"    {result['reasoning']}")
        print()