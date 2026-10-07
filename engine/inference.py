from .knowledge import THREAT_KNOWLEDGE


def normalize_text(text):
    """
    Normalize user input before rule matching.
    """
    if not isinstance(text, str):
        return ""

    return " ".join(text.lower().strip().split())


def indicator_matches(text, indicator):
    """
    Check whether an indicator is present in the input.

    Uses normalized substring matching while safely
    handling indicators containing symbols.
    """
    indicator = indicator.lower().strip()

    if not indicator:
        return False

    return indicator in text


def calculate_match_strength(matched_indicators):
    """
    Calculate a simple explainable rule-based confidence
    based on the number of matched indicators.

    This is NOT machine learning.
    """

    count = len(matched_indicators)

    if count >= 5:
        return 95

    if count >= 4:
        return 90

    if count >= 3:
        return 85

    if count >= 2:
        return 75

    if count == 1:
        return 60

    return 0


def run_inference(text):

    normalized = normalize_text(text)

    if not normalized:
        return []

    matches = []

    for threat_id, knowledge in THREAT_KNOWLEDGE.items():

        indicators = knowledge.get("indicators", [])

        matched_indicators = []

        for indicator in indicators:

            if indicator_matches(normalized, indicator):
                matched_indicators.append(indicator)

        if not matched_indicators:
            continue

        strength = calculate_match_strength(
            matched_indicators
        )

        matches.append({

            "threat_id": threat_id,

            "knowledge": knowledge,

            "indicators": matched_indicators,

            "match_count": len(
                matched_indicators
            ),

            "match_strength": strength

        })

    # --------------------------------------------------------
    # STRONGEST RULES FIRST
    # --------------------------------------------------------

    matches.sort(
        key=lambda item: (
            item["match_strength"],
            item["match_count"]
        ),
        reverse=True
    )

    return matches