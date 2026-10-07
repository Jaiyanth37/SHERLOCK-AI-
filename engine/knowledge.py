# ============================================================
# SHERLOCK CYBER INTELLIGENCE SYSTEM
# THREAT KNOWLEDGE BASE
#
# Security Heuristic Evaluation, Reasoning, Logic and
# Observation for Cybersecurity Knowledge
#
# Purpose:
# - Knowledge Representation
# - Rule-Based Reasoning
# - Pattern Matching
# - Explainable AI
# - Threat Classification
# - Cybersecurity Risk Analysis
# - MITRE ATT&CK Mapping
# ============================================================


THREAT_KNOWLEDGE = {

    # ========================================================
    # 1. AUTHENTICATION & CREDENTIAL ATTACKS
    # ========================================================

    "brute_force": {
        "name": "Brute Force",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "mitre_tactic": "Credential Access",

        "description": (
            "Repeated attempts to discover valid credentials through "
            "password guessing, credential attacks or automated "
            "authentication attempts."
        ),

        "indicators": [
            "brute force",
            "brute-force",
            "multiple failed logins",
            "multiple login attempts",
            "repeated login attempts",
            "repeated authentication failures",
            "failed login attempts",
            "many failed logins",
            "repeated password attempts",
            "password guessing",
            "guessing password",
            "credential guessing",
            "login attempts",
            "account lockout",
            "automated login attempts",
            "password cracking"
        ],

        "actions": [
            "Enable multi-factor authentication.",
            "Apply account lockout controls.",
            "Rate-limit authentication requests.",
            "Review authentication logs.",
            "Investigate suspicious source IP addresses.",
            "Force password reset when compromise is suspected."
        ]
    },


    "password_spraying": {
        "name": "Password Spraying",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1110.003",
        "mitre_name": "Password Spraying",
        "mitre_tactic": "Credential Access",

        "description": (
            "An authentication attack in which a small number of "
            "commonly used passwords are attempted against many accounts."
        ),

        "indicators": [
            "password spraying",
            "password spray",
            "same password against many accounts",
            "same password for many accounts",
            "one password multiple accounts",
            "common password multiple accounts",
            "many accounts same password",
            "password sprayed",
            "sprayed password"
        ],

        "actions": [
            "Enable multi-factor authentication.",
            "Enforce strong password policies.",
            "Monitor authentication failures across multiple accounts.",
            "Apply authentication rate limiting.",
            "Investigate suspicious authentication sources."
        ]
    },


    "credential_stuffing": {
        "name": "Credential Stuffing",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1110.004",
        "mitre_name": "Credential Stuffing",
        "mitre_tactic": "Credential Access",

        "description": (
            "Automated use of previously compromised username and "
            "password combinations against another service."
        ),

        "indicators": [
            "credential stuffing",
            "stolen credentials",
            "stolen password",
            "reused password",
            "password reuse",
            "password reused",
            "credentials reused",
            "leaked credentials",
            "breached credentials",
            "compromised credentials",
            "credential list",
            "automated credential attempts"
        ],

        "actions": [
            "Force password resets for affected accounts.",
            "Enable multi-factor authentication.",
            "Revoke suspicious sessions.",
            "Monitor authentication activity.",
            "Detect impossible login patterns.",
            "Prevent password reuse."
        ]
    },


    "credential_theft": {
        "name": "Credential Theft",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1003",
        "mitre_name": "OS Credential Dumping",
        "mitre_tactic": "Credential Access",

        "description": (
            "Activity associated with obtaining passwords, authentication "
            "tokens or other credentials without authorization."
        ),

        "indicators": [
            "credential theft",
            "credential dumping",
            "credential dump",
            "password theft",
            "password dump",
            "steal credentials",
            "credential harvesting",
            "password harvesting",
            "login credentials",
            "lsass",
            "dump credentials",
            "dump passwords",
            "stolen credentials"
        ],

        "actions": [
            "Reset affected credentials.",
            "Enable multi-factor authentication.",
            "Review authentication logs.",
            "Investigate affected endpoints.",
            "Revoke suspicious sessions.",
            "Investigate possible lateral movement."
        ]
    },


    "account_takeover": {
        "name": "Account Takeover",
        "category": "Credential Access",
        "severity": "CRITICAL",
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "mitre_tactic": "Defense Evasion",

        "description": (
            "Unauthorized control or use of a legitimate user account."
        ),

        "indicators": [
            "account hacked",
            "account compromised",
            "account takeover",
            "someone accessed my account",
            "someone logged into my account",
            "unknown login",
            "unknown device login",
            "unknown device accessed my account",
            "someone changed my password",
            "someone changed my email",
            "unauthorized account access",
            "account was taken over"
        ],

        "actions": [
            "Change the password from a trusted device.",
            "Revoke active sessions.",
            "Enable multi-factor authentication.",
            "Review recent account activity.",
            "Check account recovery settings.",
            "Investigate unauthorized access."
        ]
    },


    "mfa_abuse": {
        "name": "MFA Abuse",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1621",
        "mitre_name": "Multi-Factor Authentication Request Generation",
        "mitre_tactic": "Credential Access",

        "description": (
            "Repeated or unexpected authentication requests intended "
            "to trick a user into approving malicious authentication."
        ),

        "indicators": [
            "mfa fatigue",
            "mfa bombing",
            "many mfa requests",
            "repeated mfa requests",
            "unexpected mfa request",
            "unexpected otp",
            "otp i did not request",
            "verification code i did not request",
            "login approval i did not request",
            "mfa spam",
            "authentication request spam"
        ],

        "actions": [
            "Do not approve unexpected authentication requests.",
            "Change credentials if compromise is suspected.",
            "Review recent authentication activity.",
            "Report suspicious MFA requests.",
            "Use phishing-resistant MFA where available."
        ]
    },


    # ========================================================
    # 2. PHISHING & SOCIAL ENGINEERING
    # ========================================================

    "phishing": {
        "name": "Phishing",
        "category": "Initial Access",
        "severity": "HIGH",
        "mitre_id": "T1566",
        "mitre_name": "Phishing",
        "mitre_tactic": "Initial Access",

        "description": (
            "Attempts to obtain sensitive information or gain access "
            "through deceptive messages, links, websites or attachments."
        ),

        "indicators": [
            "phishing",
            "phishing email",
            "phishing message",
            "suspicious link",
            "suspicious url",
            "strange link",
            "unknown link",
            "fake email",
            "fake login page",
            "fake website",
            "suspicious attachment",
            "unknown attachment",
            "unexpected attachment",
            "verify your account",
            "verify your password",
            "verify credentials",
            "urgent account verification",
            "click this link",
            "click here",
            "claim your prize",
            "reset your password immediately",
            "account suspended",
            "security alert",
            "payment verification"
        ],

        "actions": [
            "Do not open suspicious links.",
            "Do not provide credentials through the message.",
            "Verify the sender using an independent trusted channel.",
            "Report the message to the security team.",
            "Reset credentials if credentials were submitted.",
            "Enable multi-factor authentication."
        ]
    },


    "spear_phishing": {
        "name": "Spear Phishing",
        "category": "Initial Access",
        "severity": "HIGH",
        "mitre_id": "T1566.002",
        "mitre_name": "Phishing: Spearphishing Link",
        "mitre_tactic": "Initial Access",

        "description": (
            "Highly targeted phishing designed for a specific person "
            "or organization using personalized information."
        ),

        "indicators": [
            "spear phishing",
            "targeted phishing",
            "personalized phishing",
            "targeted email",
            "targeted message",
            "email specifically targeting me",
            "message using my personal information",
            "personalized malicious email"
        ],

        "actions": [
            "Verify the sender independently.",
            "Do not click suspicious links.",
            "Do not open unexpected attachments.",
            "Report the message.",
            "Review whether credentials or sensitive information were exposed."
        ]
    },


    "business_email_compromise": {
        "name": "Business Email Compromise",
        "category": "Initial Access",
        "severity": "CRITICAL",
        "mitre_id": "T1566",
        "mitre_name": "Phishing",
        "mitre_tactic": "Initial Access",

        "description": (
            "Email-based impersonation or compromise used to deceive "
            "victims into transferring money or sensitive information."
        ),

        "indicators": [
            "business email compromise",
            "bec",
            "fake ceo email",
            "fake manager email",
            "fake boss email",
            "urgent payment request",
            "wire transfer request",
            "change bank account request",
            "invoice payment request",
            "fake invoice",
            "payment instructions changed",
            "executive impersonation"
        ],

        "actions": [
            "Verify payment requests through an independent channel.",
            "Do not transfer money based only on the message.",
            "Report suspected impersonation.",
            "Review email headers and account activity.",
            "Contact financial or security personnel immediately when appropriate."
        ]
    },


    "social_engineering": {
        "name": "Social Engineering",
        "category": "Social Engineering",
        "severity": "HIGH",
        "mitre_id": "T1656",
        "mitre_name": "Phishing for Information",
        "mitre_tactic": "Credential Access",

        "description": (
            "Manipulation of people into revealing information or "
            "performing actions that weaken security."
        ),

        "indicators": [
            "social engineering",
            "pretending to be support",
            "pretending to be employee",
            "pretending to be it support",
            "impersonating support",
            "impersonating employee",
            "fake support",
            "asking for my password",
            "asking for otp",
            "asking for verification code",
            "asking me to reveal credentials",
            "pretending to be my bank",
            "pretending to be administrator"
        ],

        "actions": [
            "Never share passwords or OTPs.",
            "Verify identity through an independent trusted channel.",
            "Report suspicious requests.",
            "Do not bypass security procedures because of urgency."
        ]
    },


    "online_scam": {
        "name": "Online Scam",
        "category": "Fraud",
        "severity": "HIGH",
        "mitre_id": "T1566",
        "mitre_name": "Phishing",
        "mitre_tactic": "Initial Access",

        "description": (
            "Fraudulent online activity designed to obtain money, "
            "credentials or sensitive information."
        ),

        "indicators": [
            "you won a prize",
            "send money to receive",
            "pay a fee to receive",
            "guaranteed money",
            "urgent payment",
            "gift card payment",
            "cryptocurrency payment request",
            "investment scam",
            "refund scam",
            "fake refund",
            "prize scam",
            "money transfer scam"
        ],

        "actions": [
            "Do not send money or sensitive information.",
            "Independently verify the organization.",
            "Do not trust guaranteed financial returns.",
            "Report suspected fraud."
        ]
    },


    # ========================================================
    # 3. MALWARE
    # ========================================================

    "malware": {
        "name": "Malware",
        "category": "Execution",
        "severity": "CRITICAL",
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "mitre_tactic": "Execution",

        "description": (
            "Potentially malicious software or payload designed to "
            "perform unauthorized actions on a system."
        ),

        "indicators": [
            "malware",
            "virus",
            "infected computer",
            "computer infected",
            "malicious software",
            "malicious program",
            "malicious file",
            "malicious executable",
            "suspicious executable",
            "infected file",
            "malware detected",
            "malicious payload"
        ],

        "actions": [
            "Isolate the affected endpoint.",
            "Do not execute suspicious files.",
            "Perform a trusted security scan.",
            "Investigate the file hash.",
            "Preserve forensic evidence.",
            "Review process and network activity."
        ]
    },


    "ransomware": {
        "name": "Ransomware",
        "category": "Impact",
        "severity": "CRITICAL",
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "mitre_tactic": "Impact",

        "description": (
            "Malicious activity involving unauthorized encryption of "
            "data and potential extortion."
        ),

        "indicators": [
            "ransomware",
            "files encrypted",
            "file encrypted",
            "encrypted files",
            "files locked",
            "ransom note",
            "ransom demand",
            "pay ransom",
            "pay bitcoin",
            "pay cryptocurrency",
            "encryption key",
            "your files have been encrypted"
        ],

        "actions": [
            "Immediately isolate affected systems.",
            "Disconnect impacted hosts from the network.",
            "Preserve forensic evidence.",
            "Identify the initial access vector.",
            "Restore from trusted backups where appropriate.",
            "Investigate possible lateral movement."
        ]
    },


    "trojan": {
        "name": "Trojan",
        "category": "Execution",
        "severity": "HIGH",
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "mitre_tactic": "Execution",

        "description": (
            "Malicious software disguised as legitimate software or files."
        ),

        "indicators": [
            "trojan",
            "trojan horse",
            "fake software",
            "fake application",
            "cracked software",
            "unknown executable",
            "pirated software",
            "fake installer",
            "malicious installer"
        ],

        "actions": [
            "Do not execute unknown software.",
            "Isolate the affected device if necessary.",
            "Perform a trusted security scan.",
            "Investigate suspicious processes.",
            "Remove malicious software using trusted security tools."
        ]
    },


    "spyware": {
        "name": "Spyware",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1056",
        "mitre_name": "Input Capture",
        "mitre_tactic": "Credential Access",

        "description": (
            "Software designed to secretly monitor users or collect "
            "information without authorization."
        ),

        "indicators": [
            "spyware",
            "secret monitoring",
            "monitoring without permission",
            "spying software",
            "unauthorized monitoring",
            "secretly monitoring",
            "tracking without permission"
        ],

        "actions": [
            "Investigate suspicious software and processes.",
            "Review installed applications.",
            "Perform a trusted security scan.",
            "Change sensitive credentials from a trusted device."
        ]
    },


    "keylogger": {
        "name": "Keylogger",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1056.001",
        "mitre_name": "Input Capture: Keylogging",
        "mitre_tactic": "Credential Access",

        "description": (
            "Software or activity that records keyboard input and may "
            "capture passwords or sensitive information."
        ),

        "indicators": [
            "keylogger",
            "keystroke logger",
            "records keystrokes",
            "recording keyboard",
            "keyboard monitoring",
            "logs my keystrokes",
            "keystrokes recorded"
        ],

        "actions": [
            "Investigate the affected device.",
            "Change important credentials from a trusted device.",
            "Enable MFA.",
            "Scan for malicious software.",
            "Preserve relevant forensic evidence."
        ]
    },


    "worm": {
        "name": "Worm",
        "category": "Execution",
        "severity": "CRITICAL",
        "mitre_id": "T1210",
        "mitre_name": "Exploitation of Remote Services",
        "mitre_tactic": "Lateral Movement",

        "description": (
            "Self-propagating malicious software capable of spreading "
            "between systems."
        ),

        "indicators": [
            "worm",
            "self spreading malware",
            "self-spreading malware",
            "spreads automatically",
            "spreading between computers",
            "spreads across computers",
            "malware spreading automatically"
        ],

        "actions": [
            "Isolate affected systems.",
            "Restrict unnecessary network connections.",
            "Scan potentially affected systems.",
            "Investigate the propagation path.",
            "Patch vulnerable systems."
        ]
    },


    "botnet": {
        "name": "Botnet",
        "category": "Command and Control",
        "severity": "HIGH",
        "mitre_id": "T1071",
        "mitre_name": "Application Layer Protocol",
        "mitre_tactic": "Command and Control",

        "description": (
            "A collection of compromised systems controlled remotely "
            "through attacker infrastructure."
        ),

        "indicators": [
            "botnet",
            "zombie computer",
            "infected devices controlled",
            "remote controlled computers",
            "command and control",
            "c2 server",
            "c2 communication",
            "bot network"
        ],

        "actions": [
            "Identify compromised hosts.",
            "Isolate affected systems.",
            "Investigate suspicious connections.",
            "Remove malicious software.",
            "Block confirmed command-and-control infrastructure."
        ]
    },


    # ========================================================
    # 4. NETWORK ATTACKS
    # ========================================================

    "denial_of_service": {
        "name": "Denial of Service",
        "category": "Impact",
        "severity": "HIGH",
        "mitre_id": "T1498",
        "mitre_name": "Network Denial of Service",
        "mitre_tactic": "Impact",

        "description": (
            "Activity intended to make a service or system unavailable "
            "by overwhelming its resources."
        ),

        "indicators": [
            "denial of service",
            "dos attack",
            "server unavailable",
            "website unavailable",
            "service unavailable",
            "server overloaded",
            "too many requests",
            "request flood",
            "traffic overload"
        ],

        "actions": [
            "Monitor traffic.",
            "Apply rate limiting and filtering.",
            "Use availability protection.",
            "Review network telemetry.",
            "Investigate the source of excessive traffic."
        ]
    },


    "ddos": {
        "name": "Distributed Denial of Service",
        "category": "Impact",
        "severity": "HIGH",
        "mitre_id": "T1498",
        "mitre_name": "Network Denial of Service",
        "mitre_tactic": "Impact",

        "description": (
            "Large-scale denial-of-service activity originating from "
            "multiple systems or sources."
        ),

        "indicators": [
            "ddos",
            "distributed denial",
            "distributed denial of service",
            "traffic from many devices",
            "traffic from thousands of devices",
            "massive distributed traffic",
            "distributed traffic flood",
            "massive traffic",
            "bandwidth exhaustion",
            "server overload"
        ],

        "actions": [
            "Activate DDoS protection.",
            "Filter malicious traffic.",
            "Apply rate limiting.",
            "Monitor traffic sources.",
            "Contact the network provider when necessary."
        ]
    },


    "mitm": {
        "name": "Man-in-the-Middle Attack",
        "category": "Network Attack",
        "severity": "HIGH",
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "mitre_tactic": "Credential Access",

        "description": (
            "Interception or manipulation of communication between "
            "two parties."
        ),

        "indicators": [
            "man in the middle",
            "man-in-the-middle",
            "mitm",
            "communication intercepted",
            "traffic intercepted",
            "attacker intercepting communication",
            "someone intercepting my connection",
            "intercepting traffic",
            "connection interception"
        ],

        "actions": [
            "Use secure encrypted connections.",
            "Verify certificates.",
            "Avoid untrusted networks.",
            "Investigate unexpected interception.",
            "Use secure VPN or trusted network infrastructure when appropriate."
        ]
    },


    "arp_spoofing": {
        "name": "ARP Spoofing",
        "category": "Network Attack",
        "severity": "HIGH",
        "mitre_id": "T1557.002",
        "mitre_name": "ARP Cache Poisoning",
        "mitre_tactic": "Credential Access",

        "description": (
            "Manipulation of ARP information to redirect local network "
            "traffic through an attacker-controlled system."
        ),

        "indicators": [
            "arp spoofing",
            "arp poisoning",
            "arp cache poisoning",
            "fake arp",
            "arp attack",
            "duplicate mac address",
            "unexpected mac address"
        ],

        "actions": [
            "Investigate unexpected MAC-address changes.",
            "Monitor ARP activity.",
            "Use appropriate network security controls.",
            "Verify gateway information."
        ]
    },


    "dns_spoofing": {
        "name": "DNS Spoofing",
        "category": "Network Attack",
        "severity": "HIGH",
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "mitre_tactic": "Credential Access",

        "description": (
            "Manipulation of DNS responses to redirect users toward "
            "unexpected or malicious destinations."
        ),

        "indicators": [
            "dns spoofing",
            "dns poisoning",
            "dns cache poisoning",
            "fake dns",
            "dns redirected",
            "wrong website address",
            "unexpected dns response"
        ],

        "actions": [
            "Use trusted DNS services.",
            "Verify suspicious redirects.",
            "Investigate DNS configuration changes.",
            "Review DNS logs."
        ]
    },


    "network_reconnaissance": {
        "name": "Network Service Scanning",
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre_id": "T1046",
        "mitre_name": "Network Service Scanning",
        "mitre_tactic": "Discovery",

        "description": (
            "Systematic scanning used to identify hosts, ports and "
            "network services."
        ),

        "indicators": [
            "port scan",
            "port scanning",
            "nmap scan",
            "network scan",
            "network scanning",
            "host discovery",
            "service discovery",
            "open ports",
            "service enumeration",
            "tcp scan",
            "udp scan",
            "syn scan",
            "many ports being scanned",
            "reconnaissance"
        ],

        "actions": [
            "Identify the scanning source.",
            "Review firewall and network logs.",
            "Restrict unnecessary exposed services.",
            "Investigate repeated scanning activity.",
            "Apply network segmentation."
        ]
    },


    # ========================================================
    # 5. WEB APPLICATION ATTACKS
    # ========================================================

    "sql_injection": {
        "name": "SQL Injection",
        "category": "Web Application Attack",
        "severity": "CRITICAL",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",

        "description": (
            "Manipulation of application database queries through "
            "malicious or untrusted input."
        ),

        "indicators": [
            "sql injection",
            "union select",
            "' or 1=1",
            "' or '1'='1",
            "drop table",
            "select from",
            "database injection",
            "malicious sql",
            "query manipulation",
            "database query manipulation",
            "information_schema",
            "sleep(",
            "benchmark(",
            "database input injection"
        ],

        "actions": [
            "Use parameterized queries.",
            "Validate input.",
            "Review application logs.",
            "Check database access patterns.",
            "Apply least-privilege database permissions.",
            "Securely test affected endpoints."
        ]
    },


    "xss": {
        "name": "Cross-Site Scripting",
        "category": "Web Application Attack",
        "severity": "HIGH",
        "mitre_id": "T1189",
        "mitre_name": "Drive-by Compromise",
        "mitre_tactic": "Initial Access",

        "description": (
            "Injection of malicious client-side script into web content "
            "that may execute in another user's browser."
        ),

        "indicators": [
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "cross site scripting",
            "cross-site scripting",
            "xss",
            "alert(",
            "document.cookie",
            "innerhtml",
            "script injection",
            "javascript injection"
        ],

        "actions": [
            "Apply contextual output encoding.",
            "Validate input.",
            "Implement a strong Content Security Policy.",
            "Review affected endpoints.",
            "Use secure framework escaping mechanisms."
        ]
    },


    "csrf": {
        "name": "Cross-Site Request Forgery",
        "category": "Web Application Attack",
        "severity": "HIGH",
        "mitre_id": "T1189",
        "mitre_name": "Drive-by Compromise",
        "mitre_tactic": "Initial Access",

        "description": (
            "Attack technique that causes an authenticated user's browser "
            "to perform an unintended action."
        ),

        "indicators": [
            "csrf",
            "cross site request forgery",
            "cross-site request forgery",
            "unauthorized request",
            "request without user consent",
            "forged request"
        ],

        "actions": [
            "Use CSRF tokens.",
            "Configure SameSite cookies.",
            "Validate request origin.",
            "Review authentication and session controls."
        ]
    },


    "path_traversal": {
        "name": "Path Traversal",
        "category": "Web Application Attack",
        "severity": "HIGH",
        "mitre_id": "T1006",
        "mitre_name": "Direct Volume Access",
        "mitre_tactic": "Defense Evasion",

        "description": (
            "Unauthorized access to files outside an application's "
            "intended directory."
        ),

        "indicators": [
            "path traversal",
            "directory traversal",
            "../",
            "..\\",
            "access parent directory",
            "access system files through website",
            "unexpected file access"
        ],

        "actions": [
            "Validate file paths.",
            "Canonicalize paths.",
            "Restrict filesystem permissions.",
            "Prevent unauthorized file access.",
            "Review application logs."
        ]
    },


    "command_injection": {
        "name": "Command Injection",
        "category": "Execution",
        "severity": "CRITICAL",
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution",

        "description": (
            "Untrusted input causing operating-system commands to execute."
        ),

        "indicators": [
            "command injection",
            "system command injection",
            "unexpected command execution",
            "application executing commands",
            "shell command injection",
            "os command injection",
            "command execution through input"
        ],

        "actions": [
            "Avoid shell execution with untrusted input.",
            "Validate input strictly.",
            "Use safe APIs.",
            "Apply least privilege.",
            "Review process execution logs."
        ]
    },


    # ========================================================
    # 6. COMMAND & SCRIPT EXECUTION
    # ========================================================

    "command_execution": {
        "name": "Command and Script Execution",
        "category": "Execution",
        "severity": "HIGH",
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution",

        "description": (
            "Execution of commands or scripts that may perform "
            "unauthorized actions."
        ),

        "indicators": [
            "powershell",
            "cmd.exe",
            "command shell",
            "script execution",
            "bash command",
            "shell command",
            "encoded command",
            "invoke-expression",
            "downloadstring",
            "execution policy bypass",
            "command interpreter"
        ],

        "actions": [
            "Review process creation logs.",
            "Investigate parent-child process relationships.",
            "Inspect command-line arguments.",
            "Check for encoded or obfuscated commands.",
            "Apply least privilege."
        ]
    },


    "powershell": {
        "name": "Suspicious PowerShell Activity",
        "category": "Execution",
        "severity": "HIGH",
        "mitre_id": "T1059.001",
        "mitre_name": "PowerShell",
        "mitre_tactic": "Execution",

        "description": (
            "PowerShell activity containing characteristics that may "
            "indicate suspicious or malicious execution."
        ),

        "indicators": [
            "powershell",
            "-enc",
            "-encodedcommand",
            "invoke-webrequest",
            "invoke-expression",
            "downloadstring",
            "hidden powershell",
            "base64 powershell",
            "execution policy bypass",
            "powershell encoded"
        ],

        "actions": [
            "Inspect the complete PowerShell command.",
            "Review PowerShell logging.",
            "Check process ancestry.",
            "Investigate network connections.",
            "Look for encoded or obfuscated content."
        ]
    },


    # ========================================================
    # 7. COMMAND & CONTROL
    # ========================================================

    "suspicious_network": {
        "name": "Suspicious Network Activity",
        "category": "Command and Control",
        "severity": "HIGH",
        "mitre_id": "T1071",
        "mitre_name": "Application Layer Protocol",
        "mitre_tactic": "Command and Control",

        "description": (
            "Network communication exhibiting characteristics that "
            "may indicate command-and-control or unauthorized activity."
        ),

        "indicators": [
            "command and control",
            "c2 server",
            "c2 communication",
            "suspicious outbound connection",
            "beaconing",
            "periodic connection",
            "unknown external server",
            "malicious ip",
            "suspicious domain",
            "unusual outbound traffic",
            "unknown connection",
            "unexpected connection"
        ],

        "actions": [
            "Investigate destination IP addresses.",
            "Review DNS and proxy logs.",
            "Inspect connection frequency.",
            "Check endpoint processes creating the connection.",
            "Block confirmed malicious infrastructure."
        ]
    },


    # ========================================================
    # 8. DATA & EXFILTRATION
    # ========================================================

    "data_exfiltration": {
        "name": "Potential Data Exfiltration",
        "category": "Exfiltration",
        "severity": "CRITICAL",
        "mitre_id": "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "mitre_tactic": "Exfiltration",

        "description": (
            "Potential unauthorized transfer of sensitive information "
            "from a compromised environment."
        ),

        "indicators": [
            "data exfiltration",
            "data theft",
            "data stolen",
            "large outbound transfer",
            "large data transfer",
            "sensitive data transfer",
            "sensitive data sent",
            "stolen files",
            "uploading confidential data",
            "unauthorized data transfer",
            "bulk data transfer",
            "confidential data leaked",
            "data leak",
            "data was leaked"
        ],

        "actions": [
            "Identify the affected endpoint.",
            "Review outbound network traffic.",
            "Determine what data was accessed.",
            "Preserve relevant forensic evidence.",
            "Revoke compromised credentials.",
            "Investigate destination infrastructure."
        ]
    },


    # ========================================================
    # 9. PRIVILEGE & ACCESS
    # ========================================================

    "privilege_escalation": {
        "name": "Privilege Escalation",
        "category": "Privilege Escalation",
        "severity": "CRITICAL",
        "mitre_id": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation",
        "mitre_tactic": "Privilege Escalation",

        "description": (
            "Unauthorized elevation of privileges that provides an "
            "attacker or process with greater access."
        ),

        "indicators": [
            "privilege escalation",
            "higher privileges",
            "admin privileges",
            "administrator access",
            "root access",
            "unauthorized admin",
            "elevated privileges",
            "user became administrator",
            "gained administrator privileges",
            "root privileges"
        ],

        "actions": [
            "Remove unauthorized privileges.",
            "Investigate the affected account or process.",
            "Patch relevant vulnerabilities.",
            "Apply least privilege.",
            "Review privileged account activity."
        ]
    },


    "unauthorized_access": {
        "name": "Unauthorized Access",
        "category": "Access Control",
        "severity": "HIGH",
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "mitre_tactic": "Defense Evasion",

        "description": (
            "Access to a system, account or resource without proper authorization."
        ),

        "indicators": [
            "unauthorized access",
            "access without permission",
            "access without authorization",
            "someone accessed",
            "unknown user accessed",
            "unknown account accessed",
            "someone entered the system",
            "unauthorized user",
            "unauthorized login"
        ],

        "actions": [
            "Review authentication and access logs.",
            "Revoke unauthorized access.",
            "Change affected credentials.",
            "Investigate the source.",
            "Review permissions."
        ]
    },


    "session_hijacking": {
        "name": "Session Hijacking",
        "category": "Credential Access",
        "severity": "HIGH",
        "mitre_id": "T1539",
        "mitre_name": "Steal Web Session Cookie",
        "mitre_tactic": "Credential Access",

        "description": (
            "Unauthorized use of a valid web session or stolen session token."
        ),

        "indicators": [
            "session hijacking",
            "session stolen",
            "stolen session",
            "session cookie stolen",
            "cookie stolen",
            "session token stolen",
            "stolen session token",
            "session compromised"
        ],

        "actions": [
            "Invalidate active sessions.",
            "Change credentials where appropriate.",
            "Enable MFA.",
            "Use secure session-cookie settings.",
            "Review authentication activity."
        ]
    },


    # ========================================================
    # 10. INSIDER & REMOVABLE MEDIA
    # ========================================================

    "insider_threat": {
        "name": "Insider Threat",
        "category": "Data Security",
        "severity": "HIGH",
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage Object",
        "mitre_tactic": "Collection",

        "description": (
            "Suspicious activity performed by an authorized internal "
            "user that may threaten organizational security."
        ),

        "indicators": [
            "insider threat",
            "employee stealing",
            "employee leaking",
            "employee copied data",
            "employee accessed files",
            "unauthorized employee",
            "internal user accessed",
            "employee accessed confidential",
            "employee stole data",
            "employee leaked data"
        ],

        "actions": [
            "Review access logs.",
            "Restrict unnecessary privileges.",
            "Preserve evidence.",
            "Investigate unusual data access.",
            "Follow organizational incident-response procedures."
        ]
    },


    "removable_media": {
        "name": "Removable Media Threat",
        "category": "Device Security",
        "severity": "HIGH",
        "mitre_id": "T1091",
        "mitre_name": "Replication Through Removable Media",
        "mitre_tactic": "Lateral Movement",

        "description": (
            "Unknown or suspicious removable media that may contain "
            "malware or be used to transfer sensitive information."
        ),

        "indicators": [
            "unknown usb",
            "unknown flash drive",
            "unknown pendrive",
            "suspicious usb",
            "infected usb",
            "unknown removable drive",
            "found a usb",
            "unknown removable media",
            "suspicious flash drive"
        ],

        "actions": [
            "Do not open unknown files.",
            "Do not connect suspicious devices to sensitive systems.",
            "Scan removable media using trusted security tools.",
            "Follow organizational removable-media policies."
        ]
    },


    # ========================================================
    # 11. SUPPLY CHAIN & VULNERABILITIES
    # ========================================================

    "supply_chain": {
        "name": "Supply Chain Attack",
        "category": "Software Security",
        "severity": "CRITICAL",
        "mitre_id": "T1195",
        "mitre_name": "Supply Chain Compromise",
        "mitre_tactic": "Initial Access",

        "description": (
            "Compromise of trusted software, dependencies, updates or "
            "service providers to reach downstream targets."
        ),

        "indicators": [
            "supply chain attack",
            "compromised dependency",
            "malicious package",
            "compromised software update",
            "fake software update",
            "malicious dependency",
            "compromised library",
            "malicious package update",
            "tampered software",
            "compromised vendor"
        ],

        "actions": [
            "Verify software sources.",
            "Review dependencies.",
            "Use trusted updates.",
            "Investigate suspicious packages or releases.",
            "Review software integrity."
        ]
    },


    "unpatched_vulnerability": {
        "name": "Unpatched Vulnerability",
        "category": "Vulnerability",
        "severity": "HIGH",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",

        "description": (
            "A known security weakness that remains unpatched and "
            "could potentially be exploited."
        ),

        "indicators": [
            "unpatched vulnerability",
            "unpatched system",
            "no security patch",
            "missing security patch",
            "outdated software vulnerability",
            "vulnerable software",
            "known vulnerability",
            "security update missing",
            "critical patch missing"
        ],

        "actions": [
            "Apply the vendor security update.",
            "Temporarily mitigate exposure where appropriate.",
            "Restrict unnecessary network access.",
            "Monitor exploitation attempts.",
            "Review affected systems."
        ]
    },


    "zero_day": {
        "name": "Zero-Day Vulnerability",
        "category": "Vulnerability",
        "severity": "CRITICAL",
        "mitre_id": "T1203",
        "mitre_name": "Exploitation for Client Execution",
        "mitre_tactic": "Execution",

        "description": (
            "A previously unknown or not-yet-patched vulnerability "
            "that may be exploited before an effective fix is available."
        ),

        "indicators": [
            "zero day",
            "zero-day",
            "zero day vulnerability",
            "zero-day vulnerability",
            "previously unknown vulnerability",
            "unknown vulnerability",
            "vulnerability with no patch",
            "new vulnerability",
            "no patch available"
        ],

        "actions": [
            "Apply vendor mitigations when available.",
            "Increase monitoring.",
            "Restrict unnecessary exposure.",
            "Follow trusted security advisories.",
            "Isolate affected systems when appropriate."
        ]
    },


    # ========================================================
    # 12. CLOUD / ACCOUNT SECURITY
    # ========================================================

    "suspicious_cloud_access": {
        "name": "Suspicious Cloud Account Activity",
        "category": "Cloud Security",
        "severity": "HIGH",
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "mitre_tactic": "Defense Evasion",

        "description": (
            "Unexpected activity involving a cloud account, service "
            "or cloud-hosted resource."
        ),

        "indicators": [
            "suspicious cloud login",
            "unknown cloud login",
            "unknown cloud account",
            "unusual cloud activity",
            "unexpected cloud access",
            "cloud account compromised",
            "cloud account hacked",
            "unknown aws login",
            "unknown azure login",
            "unknown google cloud login"
        ],

        "actions": [
            "Review cloud authentication logs.",
            "Revoke suspicious sessions.",
            "Rotate exposed credentials.",
            "Enable MFA.",
            "Review cloud permissions and access keys."
        ]
    },


    # ========================================================
    # 13. DATA COLLECTION
    # ========================================================

    "data_collection": {
        "name": "Suspicious Data Collection",
        "category": "Collection",
        "severity": "HIGH",
        "mitre_id": "T1114",
        "mitre_name": "Email Collection",
        "mitre_tactic": "Collection",

        "description": (
            "Unauthorized collection of sensitive files, emails or "
            "information from a system or organization."
        ),

        "indicators": [
            "collecting sensitive data",
            "collect confidential files",
            "collecting confidential information",
            "copying sensitive files",
            "copying confidential data",
            "mass file collection",
            "email collection",
            "collecting emails",
            "collecting documents"
        ],

        "actions": [
            "Review file and access logs.",
            "Restrict unnecessary permissions.",
            "Identify affected data.",
            "Preserve evidence.",
            "Investigate the user or process performing the collection."
        ]
    }
}


# ============================================================
# KNOWLEDGE BASE HELPERS
# ============================================================

def get_knowledge_base():
    """
    Return the complete Sherlock threat knowledge base.
    """
    return THREAT_KNOWLEDGE


def get_threat(threat_key):
    """
    Return one threat definition using its internal key.
    """
    return THREAT_KNOWLEDGE.get(threat_key)


def search_knowledge(query):
    """
    Search the knowledge base by threat name, category,
    severity, description, MITRE information or indicators.
    """

    if not query:
        return list(THREAT_KNOWLEDGE.values())

    query = query.lower().strip()

    results = []

    for threat in THREAT_KNOWLEDGE.values():

        searchable = " ".join([
            threat.get("name", ""),
            threat.get("category", ""),
            threat.get("severity", ""),
            threat.get("mitre_id", ""),
            threat.get("mitre_name", ""),
            threat.get("mitre_tactic", ""),
            threat.get("description", ""),
            " ".join(threat.get("indicators", [])),
            " ".join(threat.get("actions", []))
        ]).lower()

        if query in searchable:
            results.append(threat)

    return results


def get_threat_count():
    """
    Return the number of threat definitions.
    """
    return len(THREAT_KNOWLEDGE)


def get_categories():
    """
    Return all unique cybersecurity categories.
    """
    return sorted(
        set(
            threat.get("category", "Unknown")
            for threat in THREAT_KNOWLEDGE.values()
        )
    )


def get_severity_summary():
    """
    Return the number of threats by severity.
    """

    summary = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for threat in THREAT_KNOWLEDGE.values():

        severity = threat.get(
            "severity",
            "LOW"
        )

        if severity in summary:
            summary[severity] += 1

    return summary