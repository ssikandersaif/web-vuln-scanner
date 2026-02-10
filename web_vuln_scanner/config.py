"""
Global configuration for Automated Web Vulnerability Assessment Framework
Only for authorized and intentionally vulnerable targets
"""

# =========================
# SCANNER IDENTITY
# =========================
SCANNER_NAME = "EduWebVulnScanner"
SCANNER_VERSION = "1.0"
AUTHOR = "Syed Saif Sikander"

# =========================
# TARGET SAFETY SETTINGS
# =========================
ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "juice-shop",
    "dvwa"
]

BLOCKED_KEYWORDS = [
    ".gov",
    ".edu",
    "bank",
    "paypal"
]

# =========================
# HTTP SETTINGS
# =========================
DEFAULT_TIMEOUT = 5        # seconds
MAX_RETRIES = 2
VERIFY_SSL = False         # labs often use self-signed certs

DEFAULT_HEADERS = {
    "User-Agent": "EduWebVulnScanner/1.0",
    "Accept": "text/html,application/xhtml+xml",
}

# =========================
# CRAWLER SETTINGS
# =========================
MAX_CRAWL_DEPTH = 2
FOLLOW_EXTERNAL_LINKS = False

# =========================
# PAYLOAD SETTINGS
# =========================
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1"
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "\"><svg/onload=alert(1)>"
]

CMDI_PAYLOADS = [
    ";echo testcmd123",
    "|echo testcmd123"
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini"
]

# =========================
# DETECTION SETTINGS
# =========================
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate"
]

FALSE_POSITIVE_THRESHOLD = 50   # response length diff

# =========================
# RISK SCORING
# =========================
SEVERITY_MAPPING = {
    "SQL Injection": "Critical",
    "Command Injection": "Critical",
    "XSS": "High",
    "Directory Traversal": "High"
}

# =========================
# REPORT SETTINGS
# =========================
REPORT_FORMAT = "txt"     # txt / html
REPORT_PATH = "./reports/"
INCLUDE_EVIDENCE = True
