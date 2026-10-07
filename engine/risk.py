# ============================================================
# SHERLOCK RISK ENGINE
# Explainable Heuristic Risk Scoring
# ============================================================


SEVERITY_BASE = {
    "LOW": 25,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90
}


def calculate_risk(matches, ioc_confidence):

    # --------------------------------------------------------
    # NO THREAT MATCH
    # --------------------------------------------------------

    if not matches:

        return {
            "score": 10,
            "severity": "LOW",
            "confidence": ioc_confidence
        }

    # --------------------------------------------------------
    # FIND STRONGEST THREAT
    # --------------------------------------------------------

    highest = max(
        matches,
        key=lambda item: (
            SEVERITY_BASE.get(
                item["knowledge"].get(
                    "severity",
                    "LOW"
                ),
                10
            ),
            item.get(
                "match_strength",
                0
            ),
            item.get(
                "match_count",
                len(item.get("indicators", []))
            )
        )
    )

    highest_severity = highest["knowledge"].get(
        "severity",
        "LOW"
    )

    base_score = SEVERITY_BASE.get(
        highest_severity,
        10
    )

    # --------------------------------------------------------
    # INDICATOR EVIDENCE
    # --------------------------------------------------------

    total_indicators = sum(
        len(item.get("indicators", []))
        for item in matches
    )

    indicator_bonus = min(
        total_indicators * 3,
        15
    )

    # --------------------------------------------------------
    # MULTIPLE RULE SUPPORT
    # --------------------------------------------------------

    rule_bonus = min(
        max(len(matches) - 1, 0) * 4,
        12
    )

    # --------------------------------------------------------
    # INFERENCE STRENGTH
    # --------------------------------------------------------

    match_strength = highest.get(
        "match_strength",
        0
    )

    strength_bonus = 0

    if match_strength >= 90:
        strength_bonus = 5

    elif match_strength >= 75:
        strength_bonus = 3

    elif match_strength >= 60:
        strength_bonus = 1

    # --------------------------------------------------------
    # IOC CONFIDENCE CONTRIBUTION
    # --------------------------------------------------------

    confidence_bonus = 0

    if ioc_confidence >= 95:
        confidence_bonus = 5

    elif ioc_confidence >= 90:
        confidence_bonus = 3

    elif ioc_confidence >= 75:
        confidence_bonus = 1

    # --------------------------------------------------------
    # FINAL RISK SCORE
    # --------------------------------------------------------

    score = (
        base_score
        + indicator_bonus
        + rule_bonus
        + strength_bonus
        + confidence_bonus
    )

    score = min(
        100,
        score
    )

    # --------------------------------------------------------
    # FINAL SEVERITY
    # --------------------------------------------------------

    if score >= 85:
        severity = "CRITICAL"

    elif score >= 65:
        severity = "HIGH"

    elif score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # --------------------------------------------------------
    # FINAL CONFIDENCE
    # --------------------------------------------------------

    calculated_confidence = (
        55
        + min(total_indicators * 6, 24)
        + min(len(matches) * 4, 12)
        + min(match_strength // 10, 9)
    )

    confidence = max(
        ioc_confidence,
        calculated_confidence
    )

    confidence = min(
        99,
        confidence
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {
        "score": score,
        "severity": severity,
        "confidence": confidence
    }