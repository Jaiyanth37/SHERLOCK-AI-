from .classifier import classify_ioc
from .inference import run_inference
from .risk import calculate_risk
from .mitre import get_mitre_information


def analyze(threat_input):

    classification = classify_ioc(threat_input)

    matches = run_inference(threat_input)

    risk = calculate_risk(
        matches,
        classification["confidence"]
    )

    mitre = get_mitre_information(matches)

    detected_threats = []

    evidence = []

    recommendations = []

    reasoning = []

    for match in matches:

        knowledge = match["knowledge"]

        detected_threats.append({
            "name": knowledge["name"],
            "category": knowledge["category"],
            "severity": knowledge["severity"]
        })

        for indicator in match["indicators"]:

            evidence.append(indicator)

        for action in knowledge["actions"]:

            if action not in recommendations:

                recommendations.append(action)

        reasoning.append(
            f"Rule matched: {knowledge['name']} "
            f"because the input contained "
            f"{', '.join(match['indicators'])}."
        )

    if not matches:

        reasoning.append(
            "No high-confidence threat rule matched "
            "the supplied indicator."
        )

    return {

        "indicator": threat_input,

        "ioc": {
            "type": classification["type"],
            "confidence": classification["confidence"]
        },

        "risk": risk,

        "threats": detected_threats,

        "evidence": evidence,

        "mitre": mitre,

        "reasoning": reasoning,

        "recommendations": recommendations

    }