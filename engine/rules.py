"""
============================================================
SHERLOCK
Security Heuristic Evaluation, Reasoning, Logic and
Observation for Cybersecurity Knowledge
============================================================

AI approach:
- Knowledge Representation
- Rule-Based Reasoning
- Pattern Matching
- Heuristic Analysis
- IOC Classification
- Behavioural Analysis
- URL Analysis
- Explainable Reasoning
- Unknown Threat Detection
============================================================
"""

import re

from .knowledge import THREAT_KNOWLEDGE
from .classifier import classify_input


# ============================================================
# 1. SEVERITY WEIGHTS
# ============================================================

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


# ============================================================
# 2. NORMALIZE USER INPUT
# ============================================================

def normalize_text(text):
    """
    Normalize user input before Sherlock performs reasoning.
    """

    if not isinstance(text, str):
        return ""

    text = text.lower().strip()

    text = re.sub(r"\s+", " ", text)

    return text


# ============================================================
# 3. IDENTIFY USER INTENTION
# ============================================================

def detect_intent(text):

    if not text:
        return "No Input"

    # --------------------------------------------------------
    # Safety questions
    # --------------------------------------------------------

    if any(x in text for x in [
        "should i click",
        "can i click",
        "is it safe to click",
        "should i open",
        "can i open",
        "should i download",
        "can i download",
        "should i reply",
        "can i reply",
        "what should i do",
        "what do i do",
        "what now",
        "help me"
    ]):
        return "Safety Advice"

    # --------------------------------------------------------
    # Prevention
    # --------------------------------------------------------

    if any(x in text for x in [
        "how to prevent",
        "how can i prevent",
        "how do i prevent",
        "how to stop",
        "how can i stop",
        "protect against",
        "how to protect",
        "prevention",
        "prevent this"
    ]):
        return "Prevention"

    # --------------------------------------------------------
    # Information
    # --------------------------------------------------------

    if any(x in text for x in [
        "what is",
        "what does",
        "explain",
        "meaning of",
        "tell me about",
        "define",
        "what are"
    ]):
        return "Information"

    # --------------------------------------------------------
    # Threat analysis
    # --------------------------------------------------------

    return "Threat Analysis"


# ============================================================
# 4. FIND KNOWN THREAT MATCHES
# ============================================================

def find_threat_matches(text):

    matches = []

    for threat_key, data in THREAT_KNOWLEDGE.items():

        indicators = data.get("indicators", [])

        matched_indicators = []

        for indicator in indicators:

            indicator = indicator.lower().strip()

            if indicator and indicator in text:

                matched_indicators.append(indicator)

        if matched_indicators:

            matches.append({

                "threat_id": threat_key,

                "threat": data.get(
                    "name",
                    threat_key.replace("_", " ").title()
                ),

                "category": data.get(
                    "category",
                    "Unknown"
                ),

                "severity": data.get(
                    "severity",
                    "MEDIUM"
                ).upper(),

                "reason": data.get(
                    "description",
                    "A known cybersecurity indicator was detected."
                ),

                "action": " ".join(
                    data.get("actions", [])
                ),

                "actions": data.get(
                    "actions",
                    []
                ),

                "matched_indicators": matched_indicators,

                "mitre_id": data.get(
                    "mitre_id",
                    "N/A"
                ),

                "mitre_name": data.get(
                    "mitre_name",
                    "N/A"
                ),

                "mitre_tactic": data.get(
                    "mitre_tactic",
                    data.get("category", "Unknown")
                )

            })

    return matches


# ============================================================
# 5. BEHAVIOURAL KNOWLEDGE
# ============================================================

BEHAVIOR_INDICATORS = {

    "Urgency Pressure": {
        "patterns": [
            "act immediately",
            "do it now",
            "urgent",
            "immediately",
            "within 24 hours",
            "within 1 hour",
            "last warning",
            "final warning",
            "account will be closed",
            "account will be suspended"
        ],
        "weight": 2
    },

    "Credential Request": {
        "patterns": [
            "give me your password",
            "send your password",
            "share your password",
            "tell me your password",
            "send otp",
            "give me otp",
            "send verification code",
            "give me verification code",
            "share credentials",
            "send credentials",
            "enter your password",
            "enter your credentials"
        ],
        "weight": 5
    },

    "Suspicious Link": {
        "patterns": [
            "suspicious link",
            "strange link",
            "unknown link",
            "suspicious url",
            "unknown url",
            "shortened link",
            "unexpected link",
            "click this link"
        ],
        "weight": 5
    },

    "Unexpected Attachment": {
        "patterns": [
            "unexpected attachment",
            "unknown attachment",
            "suspicious attachment",
            "unexpected file",
            "unknown file",
            "strange attachment"
        ],
        "weight": 4
    },

    "Financial Pressure": {
        "patterns": [
            "send money",
            "transfer money",
            "wire transfer",
            "pay immediately",
            "payment required",
            "gift card",
            "cryptocurrency",
            "crypto payment",
            "payment verification"
        ],
        "weight": 5
    },

    "Unauthorized Access": {
        "patterns": [
            "without permission",
            "without authorization",
            "unknown person accessed",
            "unknown device",
            "unknown login",
            "someone accessed",
            "unauthorized access"
        ],
        "weight": 5
    },

    "Sensitive Data Exposure": {
        "patterns": [
            "password exposed",
            "credentials exposed",
            "personal information exposed",
            "sensitive information exposed",
            "private data exposed",
            "confidential files",
            "confidential information",
            "data leaked"
        ],
        "weight": 5
    },

    "Unexpected Software": {
        "patterns": [
            "unknown software",
            "unknown application",
            "unknown program",
            "unexpected application",
            "unexpected software",
            "unknown executable"
        ],
        "weight": 4
    },

    "Suspicious Network Behaviour": {
        "patterns": [
            "unknown connection",
            "unexpected connection",
            "strange network traffic",
            "unusual network traffic",
            "unknown server connection",
            "unexpected outbound traffic",
            "suspicious outbound connection"
        ],
        "weight": 5
    },

    "System Behaviour Change": {
        "patterns": [
            "computer suddenly became slow",
            "computer suddenly slow",
            "unknown programs started",
            "programs started automatically",
            "files suddenly changed",
            "files disappeared",
            "browser redirects",
            "browser redirected",
            "settings changed automatically"
        ],
        "weight": 4
    }
}


# ============================================================
# 6. BEHAVIOURAL ANALYSIS
# ============================================================

def analyze_behaviors(text):

    detected = []

    total_score = 0

    for name, data in BEHAVIOR_INDICATORS.items():

        matches = []

        for pattern in data["patterns"]:

            if pattern in text:

                matches.append(pattern)

        if matches:

            detected.append({

                "indicator": name,

                "matches": matches,

                "weight": data["weight"]

            })

            total_score += data["weight"]

    return detected, total_score


# ============================================================
# 7. URL ANALYSIS
# ============================================================

def analyze_urls(text):

    urls = re.findall(
        r"(?:https?://|www\.)[^\s]+",
        text,
        re.IGNORECASE
    )

    signals = []

    score = 0

    for url in urls:

        clean_url = url.rstrip(
            ".,!?;:)]}"
        )

        lower_url = clean_url.lower()

        # ----------------------------------------------------
        # HTTP instead of HTTPS
        # ----------------------------------------------------

        if lower_url.startswith("http://"):

            signals.append(
                "URL uses HTTP instead of HTTPS."
            )

            score += 2

        # ----------------------------------------------------
        # @ symbol
        # ----------------------------------------------------

        if "@" in lower_url:

            signals.append(
                "URL contains an @ symbol."
            )

            score += 3

        # ----------------------------------------------------
        # Suspicious keywords
        # ----------------------------------------------------

        if any(word in lower_url for word in [
            "login",
            "verify",
            "password",
            "account",
            "secure",
            "update",
            "claim",
            "payment",
            "signin",
            "verification"
        ]):

            signals.append(
                "URL contains a security-sensitive keyword."
            )

            score += 2

        # ----------------------------------------------------
        # IP address used as URL host
        # ----------------------------------------------------

        if re.search(
            r"https?://\d{1,3}(?:\.\d{1,3}){3}",
            lower_url
        ):

            signals.append(
                "URL uses an IP address instead of a domain name."
            )

            score += 3

        # ----------------------------------------------------
        # Excessive subdomains
        # ----------------------------------------------------

        try:

            host = re.sub(
                r"^https?://",
                "",
                lower_url
            ).split("/")[0]

            labels = host.split(".")

            if len(labels) >= 4:

                signals.append(
                    "URL contains an unusually large number of subdomains."
                )

                score += 2

        except Exception:
            pass

    return signals, score


# ============================================================
# 8. CONFIDENCE CALCULATION
# ============================================================

def calculate_confidence(
    matches,
    behavior_score,
    url_score
):

    if not matches:

        return 0

    indicator_count = sum(
        len(item["matched_indicators"])
        for item in matches
    )

    confidence = 50

    # More matching indicators = stronger evidence
    confidence += min(
        indicator_count * 6,
        30
    )

    # Behavioural evidence
    confidence += min(
        behavior_score * 2,
        10
    )

    # URL evidence
    confidence += min(
        url_score * 2,
        8
    )

    # Multiple independent rules
    if len(matches) >= 2:

        confidence += 5

    if len(matches) >= 3:

        confidence += 3

    return min(
        confidence,
        98
    )


# ============================================================
# 9. SELECT STRONGEST THREAT
# ============================================================

def select_strongest_match(matches):

    return max(
        matches,
        key=lambda item: (
            SEVERITY_WEIGHT.get(
                item["severity"].upper(),
                1
            ),
            len(item["matched_indicators"])
        )
    )


# ============================================================
# 10. UNKNOWN / HEURISTIC REASONING
# ============================================================

def analyze_unknown_behavior(
    behavior_score,
    url_score,
    behaviors,
    url_signals
):

    total_score = (
        behavior_score +
        url_score
    )

    signals = [
        item["indicator"]
        for item in behaviors
    ]

    if url_signals:

        signals.extend(
            url_signals
        )

    # --------------------------------------------------------
    # HIGH SUSPICION
    # --------------------------------------------------------

    if total_score >= 10:

        return {

            "threat":
                "Potential Unknown Threat",

            "level":
                "HIGH",

            "confidence":
                min(
                    90,
                    45 + total_score * 3
                ),

            "reason":
                (
                    "Sherlock could not confidently map the "
                    "situation to a specific known attack, "
                    "but multiple independent security indicators "
                    "suggest potentially malicious activity."
                ),

            "action":
                (
                    "Do not interact with suspicious content. "
                    "If compromise is suspected, isolate the "
                    "affected system, preserve relevant evidence, "
                    "verify the source independently, and escalate "
                    "the incident for investigation."
                ),

            "signals":
                signals
        }

    # --------------------------------------------------------
    # MEDIUM SUSPICION
    # --------------------------------------------------------

    if total_score >= 5:

        return {

            "threat":
                "Suspicious Activity",

            "level":
                "MEDIUM",

            "confidence":
                min(
                    80,
                    35 + total_score * 4
                ),

            "reason":
                (
                    "Sherlock did not identify a specific known "
                    "attack, but suspicious cybersecurity "
                    "behaviour was detected."
                ),

            "action":
                (
                    "Avoid interacting with suspicious content, "
                    "verify the source independently, review "
                    "relevant activity, and continue monitoring."
                ),

            "signals":
                signals
        }

    # --------------------------------------------------------
    # LOW / NO STRONG EVIDENCE
    # --------------------------------------------------------

    return {

        "threat":
            "No Strong Threat Indicators Detected",

        "level":
            "LOW",

        "confidence":
            20,

        "reason":
            (
                "Sherlock did not find enough evidence to "
                "classify the situation as a significant "
                "cybersecurity threat."
            ),

        "action":
            (
                "Continue following normal cybersecurity "
                "practices and monitor for additional "
                "suspicious activity."
            ),

        "signals":
            signals
    }


# ============================================================
# 11. SAFETY OVERRIDE
# ============================================================

def apply_safety_override(result, text):

    suspicious_link = any(
        x in text
        for x in [
            "suspicious link",
            "unknown link",
            "strange link",
            "suspicious url",
            "unknown url"
        ]
    )

    asking_to_click = any(
        x in text
        for x in [
            "should i click",
            "can i click",
            "is it safe to click"
        ]
    )

    suspicious_attachment = any(
        x in text
        for x in [
            "suspicious attachment",
            "unknown attachment",
            "unexpected attachment"
        ]
    )

    asking_to_open = any(
        x in text
        for x in [
            "should i open",
            "can i open"
        ]
    )

    # --------------------------------------------------------
    # Suspicious link override
    # --------------------------------------------------------

    if suspicious_link and asking_to_click:

        result["level"] = "HIGH"

        result["action"] = (
            "DO NOT click the suspicious link. "
            "Verify the sender through an independent trusted "
            "channel and visit the official website manually."
        )

        result["reason"] = (
            "The user identified the link as suspicious and "
            "is considering interacting with it. This is a "
            "strong warning sign for phishing or social engineering."
        )

    # --------------------------------------------------------
    # Suspicious attachment override
    # --------------------------------------------------------

    if suspicious_attachment and asking_to_open:

        result["level"] = "HIGH"

        result["action"] = (
            "DO NOT open the suspicious attachment. "
            "Verify the sender independently and scan the file "
            "using trusted security tools before opening it."
        )

        result["reason"] = (
            "The user identified an attachment as suspicious "
            "and is considering opening it. This presents a "
            "potential malware or phishing risk."
        )

    return result


# ============================================================
# 12. MAIN SHERLOCK ENGINE
# ============================================================

def analyze_threat(situation):

    # --------------------------------------------------------
    # INPUT CHECK
    # --------------------------------------------------------

    if not isinstance(
        situation,
        str
    ) or not situation.strip():

        return {

            "threat":
                "No Input Provided",

            "level":
                "LOW",

            "confidence":
                0,

            "reason":
                (
                    "Sherlock did not receive a cybersecurity "
                    "situation."
                ),

            "action":
                (
                    "Enter a cybersecurity situation, warning, "
                    "message, event, or suspicious activity."
                ),

            "category":
                "Input",

            "matched_indicators":
                [],

            "behavior_indicators":
                [],

            "url_indicators":
                [],

            "related_threats":
                [],

            "question_type":
                "No Input",

            "ioc":
                {
                    "type": "UNKNOWN",
                    "confidence": 0,
                    "items": []
                }
        }

    # --------------------------------------------------------
    # NORMALIZATION
    # --------------------------------------------------------

    text = normalize_text(
        situation
    )

    # --------------------------------------------------------
    # IOC CLASSIFICATION
    # --------------------------------------------------------

    ioc_result = classify_input(
        text
    )

    # --------------------------------------------------------
    # KNOWN THREAT ANALYSIS
    # --------------------------------------------------------

    matches = find_threat_matches(
        text
    )

    # --------------------------------------------------------
    # BEHAVIOURAL ANALYSIS
    # --------------------------------------------------------

    behaviors, behavior_score = analyze_behaviors(
        text
    )

    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    url_signals, url_score = analyze_urls(
        text
    )

    # ========================================================
    # KNOWN THREAT FOUND
    # ========================================================

    if matches:

        strongest = select_strongest_match(
            matches
        )

        confidence = calculate_confidence(
            matches,
            behavior_score,
            url_score
        )

        result = {

            "threat":
                strongest["threat"],

            "level":
                strongest["severity"],

            "confidence":
                confidence,

            "reason":
                strongest["reason"],

            "action":
                strongest["action"],

            "category":
                strongest["category"],

            "matched_indicators":
                strongest["matched_indicators"],

            "behavior_indicators":
                [
                    item["indicator"]
                    for item in behaviors
                ],

            "url_indicators":
                url_signals,

            "related_threats":
                [
                    item["threat"]
                    for item in matches
                    if item["threat"]
                    != strongest["threat"]
                ][:5],

            "question_type":
                detect_intent(text),

            "ioc":
                {
                    "type":
                        ioc_result["primary_type"],

                    "confidence":
                        ioc_result["confidence"],

                    "items":
                        ioc_result["iocs"]
                },

            "mitre":
                {
                    "id":
                        strongest["mitre_id"],

                    "name":
                        strongest["mitre_name"],

                    "tactic":
                        strongest["mitre_tactic"]
                }
        }

        return apply_safety_override(
            result,
            text
        )

    # ========================================================
    # NO KNOWN THREAT
    # HEURISTIC REASONING
    # ========================================================

    unknown = analyze_unknown_behavior(

        behavior_score,

        url_score,

        behaviors,

        url_signals
    )

    result = {

        "threat":
            unknown["threat"],

        "level":
            unknown["level"],

        "confidence":
            unknown["confidence"],

        "reason":
            unknown["reason"],

        "action":
            unknown["action"],

        "category":
            "Unknown / Behavioural Analysis",

        "matched_indicators":
            [],

        "behavior_indicators":
            unknown["signals"],

        "url_indicators":
            url_signals,

        "related_threats":
            [],

        "question_type":
            detect_intent(text),

        "ioc":
            {
                "type":
                    ioc_result["primary_type"],

                "confidence":
                    ioc_result["confidence"],

                "items":
                    ioc_result["iocs"]
            },

        "mitre":
            []
    }

    return apply_safety_override(
        result,
        text
    )