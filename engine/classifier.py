"""
============================================================
SHERLOCK CYBER INTELLIGENCE SYSTEM
IOC CLASSIFIER
============================================================

Identifies common Indicators of Compromise (IOCs):

- IPv4 addresses
- Email addresses
- URLs
- Domains
- MD5 hashes
- SHA-1 hashes
- SHA-256 hashes
- File names
- IP addresses embedded in text

This module is designed to work with Sherlock's
rule-based reasoning engine.
============================================================
"""

import re


# ============================================================
# 1. IOC PATTERNS
# ============================================================

IPV4_PATTERN = re.compile(
    r"(?<!\d)"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"){3}"
    r"(?!\d)"
)


EMAIL_PATTERN = re.compile(
    r"\b"
    r"[A-Za-z0-9._%+-]+"
    r"@"
    r"[A-Za-z0-9.-]+"
    r"\.[A-Za-z]{2,}"
    r"\b"
)


DOMAIN_PATTERN = re.compile(
    r"\b"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"[a-zA-Z]{2,}"
    r"\b"
)


MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)


SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)


SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


URL_PATTERN = re.compile(
    r"\b"
    r"(?:https?|ftp)://"
    r"[^\s]+",
    re.IGNORECASE
)


# ============================================================
# 2. SINGLE-VALUE CLASSIFICATION
# ============================================================

def classify_ioc(value):

    if not isinstance(value, str):
        return {
            "type": "UNKNOWN",
            "confidence": 0
        }

    value = value.strip()

    if not value:
        return {
            "type": "UNKNOWN",
            "confidence": 0
        }

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if re.fullmatch(
        r"(?:https?|ftp)://[^\s]+",
        value,
        re.IGNORECASE
    ):

        return {
            "type": "URL",
            "confidence": 99
        }

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    if IPV4_PATTERN.fullmatch(value):

        return {
            "type": "IPv4",
            "confidence": 99
        }

    # --------------------------------------------------------
    # EMAIL
    # --------------------------------------------------------

    if EMAIL_PATTERN.fullmatch(value):

        return {
            "type": "EMAIL",
            "confidence": 99
        }

    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    if SHA256_PATTERN.fullmatch(value):

        return {
            "type": "SHA-256",
            "confidence": 99
        }

    # --------------------------------------------------------
    # SHA-1
    # --------------------------------------------------------

    if SHA1_PATTERN.fullmatch(value):

        return {
            "type": "SHA-1",
            "confidence": 99
        }

    # --------------------------------------------------------
    # MD5
    # --------------------------------------------------------

    if MD5_PATTERN.fullmatch(value):

        return {
            "type": "MD5",
            "confidence": 99
        }

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    if DOMAIN_PATTERN.fullmatch(value):

        return {
            "type": "DOMAIN",
            "confidence": 95
        }

    # --------------------------------------------------------
    # TEXT
    # --------------------------------------------------------

    return {
        "type": "TEXT",
        "confidence": 90
    }


# ============================================================
# 3. EXTRACT IOCs FROM TEXT
# ============================================================

def extract_iocs(text):

    if not isinstance(text, str):
        return []

    text = text.strip()

    if not text:
        return []

    found = []

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    for value in URL_PATTERN.findall(text):

        value = value.rstrip(
            ".,!?;:)]}"
        )

        found.append({
            "value": value,
            "type": "URL",
            "confidence": 99
        })

    # --------------------------------------------------------
    # EMAILS
    # --------------------------------------------------------

    for value in EMAIL_PATTERN.findall(text):

        found.append({
            "value": value,
            "type": "EMAIL",
            "confidence": 99
        })

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    for value in IPV4_PATTERN.findall(text):

        found.append({
            "value": value,
            "type": "IPv4",
            "confidence": 99
        })

    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    for value in SHA256_PATTERN.findall(text):

        found.append({
            "value": value,
            "type": "SHA-256",
            "confidence": 99
        })

    # --------------------------------------------------------
    # SHA-1
    # --------------------------------------------------------

    for value in SHA1_PATTERN.findall(text):

        found.append({
            "value": value,
            "type": "SHA-1",
            "confidence": 99
        })

    # --------------------------------------------------------
    # MD5
    # --------------------------------------------------------

    for value in MD5_PATTERN.findall(text):

        found.append({
            "value": value,
            "type": "MD5",
            "confidence": 99
        })

    # --------------------------------------------------------
    # DOMAINS
    # --------------------------------------------------------

    for value in DOMAIN_PATTERN.findall(text):

        # Don't duplicate domains that are already part
        # of an email address.

        if "@" in text[
            max(0, text.find(value) - 1):
            text.find(value) + len(value) + 1
        ]:
            continue

        # Avoid treating file extensions as domains.
        if value.lower().endswith(
            (
                ".exe",
                ".dll",
                ".zip",
                ".rar",
                ".txt",
                ".pdf",
                ".doc",
                ".docx"
            )
        ):
            continue

        found.append({
            "value": value,
            "type": "DOMAIN",
            "confidence": 95
        })

    # --------------------------------------------------------
    # REMOVE DUPLICATES
    # --------------------------------------------------------

    unique = []

    seen = set()

    for item in found:

        key = (
            item["value"].lower(),
            item["type"]
        )

        if key not in seen:

            seen.add(key)

            unique.append(item)

    return unique


# ============================================================
# 4. CLASSIFY COMPLETE INPUT
# ============================================================

def classify_input(text):

    if not isinstance(text, str):
        return {
            "primary_type": "UNKNOWN",
            "confidence": 0,
            "iocs": []
        }

    text = text.strip()

    if not text:
        return {
            "primary_type": "UNKNOWN",
            "confidence": 0,
            "iocs": []
        }

    # First check whether the entire input is one IOC.

    direct = classify_ioc(text)

    if direct["type"] != "TEXT":

        return {
            "primary_type": direct["type"],
            "confidence": direct["confidence"],
            "iocs": [
                {
                    "value": text,
                    "type": direct["type"],
                    "confidence": direct["confidence"]
                }
            ]
        }

    # Otherwise search inside the complete sentence.

    iocs = extract_iocs(text)

    if not iocs:

        return {
            "primary_type": "TEXT",
            "confidence": 90,
            "iocs": []
        }

    # Highest-confidence IOC becomes primary type.

    primary = max(
        iocs,
        key=lambda item: item["confidence"]
    )

    return {
        "primary_type": primary["type"],
        "confidence": primary["confidence"],
        "iocs": iocs
    }