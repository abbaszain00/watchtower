# Priority scoring based on FIRST.org EPSS thresholds + CISA KEV
# CRITICAL = in KEV, HIGH = EPSS >= 0.2 AND CVSS >= 6, MEDIUM = one of those, LOW = neither

EPSS_THRESHOLD = 0.2
CVSS_THRESHOLD = 6.0


def extract_cvss_score(severity_data):
    if not severity_data:
        return None

    best = None
    for entry in severity_data:
        score = _estimate_cvss_from_vector(entry.get("score", ""))
        if score and (best is None or score > best):
            best = score
    return best


def _estimate_cvss_from_vector(vector):
    # Rough estimate from v3.x or v4.0 vector — not a full calculator
    if "CVSS:3" not in vector and "CVSS:4" not in vector:
        return None

    try:
        metrics = {}
        for part in vector.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k] = v

        score = 0

        impact_keys = ["VC", "VI", "VA"] if "CVSS:4" in vector else ["C", "I", "A"]
        for key in impact_keys:
            val = metrics.get(key, "N")
            if val == "H":
                score += 3.0
            elif val == "L":
                score += 1.0

        if metrics.get("AV") == "N":
            score += 1.0
        elif metrics.get("AV") == "A":
            score += 0.5

        if metrics.get("AC") == "L":
            score += 0.5

        if metrics.get("PR") == "N":
            score += 0.5

        return min(10.0, score)

    except Exception:
        return None


def calculate_priority(finding):
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
    tests = [
        {"name": "KEV hit", "in_kev": True, "epss": 0.936,
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
        {"name": "High EPSS + CVSS", "in_kev": False, "epss": 0.45,
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}]},
        {"name": "High CVSS, low EPSS", "in_kev": False, "epss": 0.05,
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
        {"name": "High EPSS, low CVSS", "in_kev": False, "epss": 0.35,
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]},
        {"name": "Low on both", "in_kev": False, "epss": 0.02,
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]},
    ]

    print(f"Scoring test — EPSS >= {EPSS_THRESHOLD:.0%}, CVSS >= {CVSS_THRESHOLD}\n")
    for t in tests:
        r = calculate_priority(t)
        print(f"  [{r['priority']}] {t['name']}")
        print(f"    CVSS: {r['cvss_score']}, EPSS: {t.get('epss')}, KEV: {t.get('in_kev')}")
        print(f"    {r['reasoning']}\n")