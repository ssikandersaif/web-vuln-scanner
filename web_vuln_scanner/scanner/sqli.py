from utils.rate_limiter import rate_limited_request

# SQL error messages - if we see these, it's DEFINITELY vulnerable
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "sqlite3",
    "sqlite_error",  # Juice Shop uses SQLite
    "postgresql",
    "ora-00933",  # Oracle
    "microsoft sql server",
    "syntax error",  # Generic SQL syntax error
]

def test_sqli(session, url, param, base_url=None):
    """
    Test for SQL injection vulnerability.
    
    Returns:
        dict with: vulnerable (bool), confidence (HIGH/MEDIUM/LOW), evidence (str)
        Or just True/False for backward compatibility
    """
    
    # Use rate-limited requests
    normal = rate_limited_request(session, "GET", url, params={param: "1", "Submit": "Submit"})
    
    if normal is None:
        return False
    
    # Test basic single quote for SQL errors
    payload = "'"
    injected = rate_limited_request(session, "GET", url, params={param: payload, "Submit": "Submit"})
    
    if injected:
        injected_lower = injected.text.lower()
        for error in SQL_ERRORS:
            if error in injected_lower:
                return {
                    "vulnerable": True,
                    "confidence": "HIGH",
                    "evidence": f"SQL error message found: '{error}'",
                    "payload": payload
                }
    
    # Try more aggressive payloads for different SQL contexts (e.g., Juice Shop)
    aggressive_payloads = ["))", ")", ")--", ")) OR 1=1--", "'))"]
    for test_payload in aggressive_payloads:
        injected2 = rate_limited_request(session, "GET", url, params={param: test_payload, "Submit": "Submit"})
        if injected2:
            injected2_lower = injected2.text.lower()
            for error in SQL_ERRORS:
                if error in injected2_lower:
                    return {
                        "vulnerable": True,
                        "confidence": "HIGH",
                        "evidence": f"SQL error message found: '{error}'",
                        "payload": test_payload
                    }
    
    # Check response length difference (MEDIUM confidence) only if no SQL errors found
    if injected:
        len_diff = abs(len(injected.text) - len(normal.text))
        if len_diff > 100:
            # Also check if normal response has actual content
            if len(normal.text) > 500:
                return {
                    "vulnerable": True,
                    "confidence": "MEDIUM",
                    "evidence": f"Response length changed by {len_diff} bytes",
                    "payload": payload
                }
    
    # Try a more aggressive payload for additional check
    payload2 = "' OR '1'='1"
    injected2 = rate_limited_request(session, "GET", url, params={param: payload2, "Submit": "Submit"})
    
    if injected2 and len(injected2.text) != len(normal.text):
        # Check if we get MORE data back (sign of successful injection)
        if len(injected2.text) > len(normal.text) + 50:
            return {
                "vulnerable": True,
                "confidence": "MEDIUM",
                "evidence": f"OR payload returned more data ({len(injected2.text)} vs {len(normal.text)} bytes)",
                "payload": payload2
            }
    
    return {"vulnerable": False, "confidence": "NONE", "evidence": "No signs of SQL injection"}
