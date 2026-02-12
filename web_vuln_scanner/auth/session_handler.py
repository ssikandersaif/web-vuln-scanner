import requests
from bs4 import BeautifulSoup

def create_session():
    """Create and return a new session"""
    session = requests.Session()
    return session
def get_csrf_token(session,url):
     """
    Fetch a page and extract the CSRF token (user_token).
    
    Args:
        session: The requests session
        url: The page URL containing the form
    
    Returns:
        The CSRF token string, or None if not found
    """
     response = session.get(url)
     soup = BeautifulSoup(response.text,"html.parser")
     # Find the hidden input field named 'user_token'
     token_field = soup.find("input",{"name":"user_token"}) 
     if token_field:
          return token_field.get("value")
     return None

def login_dvwa(session, base_url, username="admin", password="password"):
    """
    Login to DVWA.
    
    Args:
        session: The requests session
        base_url: DVWA base URL (e.g., http://localhost/dvwa)
        username: DVWA username (default: admin)
        password: DVWA password (default: password)
    
    Returns:
        True if login successful, False otherwise
    """
    login_url = base_url + "/login.php"
    
    # Step 1: Get the CSRF token from login page
    token = get_csrf_token(session, login_url)
    
    # Step 2: Prepare login data
    login_data = {
        "username": username,
        "password": password,
        "Login": "Login"
    }
    
    # Add CSRF token only if found (some DVWA versions don't have it)
    if token:
        login_data["user_token"] = token
    
    # Step 3: Submit the login form
    response = session.post(login_url, data=login_data)
    
    # Step 4: Check if login worked
    if "Welcome" in response.text or "index.php" in response.url:
        print(f"[+] Logged into DVWA as '{username}'")
        return True
    else:
        print("[!] DVWA login failed")
        return False
def set_dvwa_security(session, base_url, level="low"):
    """
    Set DVWA security level.
    
    Args:
        session: The requests session (must be logged in)
        base_url: DVWA base URL
        level: Security level - 'low', 'medium', 'high', or 'impossible'
    
    Returns:
        True if successful
    """
    security_url = base_url + "/security.php"
    
    # Get CSRF token from security page
    token = get_csrf_token(session, security_url)
    
    # Submit the security level change
    data = {
        "security": level,
        "seclev_submit": "Submit",
        "user_token": token
    }
    
    session.post(security_url, data=data)
    print(f"[+] DVWA security set to '{level}'")
    return True

def login_bwapp(session, base_url, username="bee", password="bug"):
    """
    Login to bWAPP (buggy Web Application).
    
    Args:
        session: The requests session
        base_url: bWAPP URL (e.g., http://localhost/bWAPP)
        username: bWAPP username (default: bee)
        password: bWAPP password (default: bug)
    
    Returns:
        True if login successful, False otherwise
    """
    login_url = base_url + "/login.php"
    
    # bWAPP uses simple form-based login (no CSRF)
    login_data = {
        "login": username,
        "password": password,
        "security_level": "0",  # 0=low, 1=medium, 2=high
        "form": "submit"
    }
    
    response = session.post(login_url, data=login_data)
    
    # Check if login worked (bWAPP redirects or shows welcome message)
    if "Welcome" in response.text or "logged in" in response.text.lower():
        print(f"[+] Logged into bWAPP as '{username}'")
        return True
    else:
        print("[!] bWAPP login failed")
        return False


def login_mutillidae(session, base_url, username="admin", password="admin"):
    """
    Login to Mutillidae (on Metasploitable 2).
    
    Args:
        session: The requests session
        base_url: Mutillidae URL (e.g., http://192.168.1.100/mutillidae)
        username: Username (default: admin)
        password: Password (default: admin)
    
    Returns:
        True if login successful, False otherwise
    """
    login_url = base_url + "/index.php?page=login.php"
    
    login_data = {
        "username": username,
        "password": password,
        "login-php-submit-button": "Login"
    }
    
    response = session.post(login_url, data=login_data)
    
    if "Logged In" in response.text or username in response.text:
        print(f"[+] Logged into Mutillidae as '{username}'")
        return True
    else:
        print("[!] Mutillidae login failed")
        return False
