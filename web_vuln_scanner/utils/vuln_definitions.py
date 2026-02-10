"""
Vulnerability Definitions & OWASP Mapping
=========================================

This file contains:
1. OWASP Top 10 categories
2. Confidence levels for findings
3. Vulnerability information

Think of this as a "dictionary" that explains each vulnerability.
"""


# ============================================================
# OWASP TOP 10 (2021) Categories
# ============================================================
# These are the 10 most dangerous web vulnerabilities
# Every security professional knows these!

OWASP_TOP_10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Users can access things they shouldn't be able to access.",
        "example": "Viewing another user's profile by changing the ID in the URL."
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Sensitive data is not properly encrypted.",
        "example": "Storing passwords in plain text."
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "Attacker injects malicious code that gets executed.",
        "example": "SQL Injection, XSS, Command Injection."
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "The application was designed without security in mind.",
        "example": "No rate limiting on password reset."
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Security settings are wrong or missing.",
        "example": "Default passwords, verbose error messages."
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using old libraries with known vulnerabilities.",
        "example": "Using an old version of jQuery with XSS bugs."
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Login and session management is broken.",
        "example": "Weak passwords allowed, session doesn't expire."
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code or data can be modified without detection.",
        "example": "Auto-update without signature verification."
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Attacks are not detected or logged.",
        "example": "No logs of failed login attempts."
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Server is tricked into making requests to internal systems.",
        "example": "Fetching a URL that points to localhost."
    }
}


# ============================================================
# Confidence Levels
# ============================================================
# How sure are we that this is a real vulnerability?

CONFIDENCE_LEVELS = {
    "HIGH": {
        "score": 3,
        "label": "HIGH",
        "color": "🔴",
        "meaning": "Very likely a real vulnerability. Strong evidence found.",
        "false_positive_risk": "Low"
    },
    "MEDIUM": {
        "score": 2,
        "label": "MEDIUM",
        "color": "🟡",
        "meaning": "Probably a vulnerability. Some evidence found.",
        "false_positive_risk": "Medium"
    },
    "LOW": {
        "score": 1,
        "label": "LOW",
        "color": "🟢",
        "meaning": "Might be a vulnerability. Weak evidence.",
        "false_positive_risk": "High"
    }
}


# ============================================================
# Vulnerability Definitions
# ============================================================
# Information about each type of vulnerability we scan for

VULNERABILITY_INFO = {
    "sqli": {
        "name": "SQL Injection",
        "short_name": "SQLi",
        "owasp": "A03",
        "severity": "Critical",
        "description": "Attacker can inject SQL code to read/modify the database.",
        "impact": "Data theft, data loss, complete system compromise.",
        "remediation": "Use parameterized queries (prepared statements).",
        "cwe": "CWE-89"
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "short_name": "XSS",
        "owasp": "A03",
        "severity": "High",
        "description": "Attacker can inject JavaScript that runs in user's browser.",
        "impact": "Session hijacking, defacement, malware distribution.",
        "remediation": "Encode output, use Content Security Policy.",
        "cwe": "CWE-79"
    },
    "cmdi": {
        "name": "Command Injection",
        "short_name": "CMDi",
        "owasp": "A03",
        "severity": "Critical",
        "description": "Attacker can execute operating system commands on the server.",
        "impact": "Complete server compromise, data theft, lateral movement.",
        "remediation": "Avoid shell commands, use safe APIs, validate input.",
        "cwe": "CWE-78"
    },
    "traversal": {
        "name": "Path Traversal",
        "short_name": "LFI",
        "owasp": "A01",
        "severity": "High",
        "description": "Attacker can read files outside the web directory.",
        "impact": "Source code disclosure, configuration file access, credentials theft.",
        "remediation": "Validate file paths, use allowlists, chroot jail.",
        "cwe": "CWE-22"
    }
}


def get_owasp_info(owasp_id):
    """
    Get information about an OWASP category.
    
    Example:
        info = get_owasp_info("A03")
        print(info["name"])  # "Injection"
    """
    return OWASP_TOP_10.get(owasp_id, {})


def get_vuln_info(vuln_type):
    """
    Get information about a vulnerability type.
    
    Example:
        info = get_vuln_info("sqli")
        print(info["owasp"])  # "A03"
    """
    return VULNERABILITY_INFO.get(vuln_type, {})


def get_confidence_info(level):
    """
    Get information about a confidence level.
    
    Example:
        info = get_confidence_info("HIGH")
        print(info["color"])  # "🔴"
    """
    return CONFIDENCE_LEVELS.get(level.upper(), CONFIDENCE_LEVELS["LOW"])
