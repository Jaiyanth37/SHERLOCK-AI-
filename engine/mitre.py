# ============================================================
# SHERLOCK MITRE ATT&CK MAPPING ENGINE
# ============================================================


# Additional MITRE information for techniques that may
# not already be fully described in the knowledge base.

MITRE_DATABASE = {

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access"
    },

    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "T1110.004": {
        "name": "Credential Stuffing",
        "tactic": "Credential Access"
    },

    "T1204": {
        "name": "User Execution",
        "tactic": "Execution"
    },

    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact"
    },

    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact"
    },

    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access"
    },

    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access"
    },

    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access"
    },

    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery"
    },

    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },

    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution"
    },

    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },

    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration"
    }
}


def get_mitre_information(matches):

    techniques = []

    seen = set()

    for match in matches:

        knowledge = match.get(
            "knowledge",
            {}
        )

        mitre_id = knowledge.get(
            "mitre_id"
        )

        if not mitre_id:
            continue

        # ----------------------------------------------------
        # Prefer information stored in the knowledge base
        # ----------------------------------------------------

        mitre_name = knowledge.get(
            "mitre_name"
        )

        mitre_tactic = knowledge.get(
            "mitre_tactic"
        )

        # ----------------------------------------------------
        # Fall back to MITRE database
        # ----------------------------------------------------

        if not mitre_name or not mitre_tactic:

            information = MITRE_DATABASE.get(
                mitre_id,
                {}
            )

            mitre_name = mitre_name or information.get(
                "name",
                "Unknown Technique"
            )

            mitre_tactic = mitre_tactic or information.get(
                "tactic",
                "Unknown Tactic"
            )

        # ----------------------------------------------------
        # Avoid duplicate techniques
        # ----------------------------------------------------

        if mitre_id in seen:
            continue

        seen.add(mitre_id)

        techniques.append({

            "id": mitre_id,

            "name": mitre_name,

            "tactic": mitre_tactic

        })

    return techniques