"""
Form Scanner - Finds and tests forms on web pages
=================================================
This file helps us find forms on websites and test them for vulnerabilities.

Think of it like this:
- A form is like a paper form you fill out (name, email, etc.)
- We find all the blanks (input fields) on the form
- We try to put bad stuff in each blank to see if the website breaks
"""

from bs4 import BeautifulSoup
from utils.rate_limiter import rate_limited_request


def get_forms(session, url):
    """
    Find all forms on a web page.
    
    It's like going to a website and finding all the 
    "fill in the blank" sections.
    
    Example form on a website:
        [Username: ________]
        [Password: ________]
        [  Login Button   ]
    """
    # Step 1: Download the web page (with rate limiting!)
    response = rate_limited_request(session, "GET", url)
    
    if response is None:
        return []
    
    # Step 2: Use BeautifulSoup to read the HTML (like reading a recipe)
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Step 3: Find all <form> tags (these are the forms!)
    forms = soup.find_all("form")
    
    return forms


def get_form_details(form):
    """
    Get all the details about one form.
    
    Returns a simple dictionary with:
    - action: where the form sends data (like a mailing address)
    - method: how it sends data (GET = in URL, POST = hidden)
    - inputs: all the blanks you can fill in
    """
    details = {}
    
    # Where does the form send data?
    details["action"] = form.get("action", "")
    
    # How does it send? GET or POST?
    details["method"] = form.get("method", "GET").upper()
    
    # Find all the input fields (the blanks to fill in)
    details["inputs"] = []
    
    # Look for <input> tags (text boxes, hidden fields, etc.)
    for input_tag in form.find_all("input"):
        input_info = {
            "name": input_tag.get("name"),      # The field's name
            "type": input_tag.get("type", "text"),  # Type of field
            "value": input_tag.get("value", "")     # Default value
        }
        details["inputs"].append(input_info)
    
    # Look for <textarea> tags (big text boxes)
    for textarea in form.find_all("textarea"):
        input_info = {
            "name": textarea.get("name"),
            "type": "textarea",
            "value": textarea.text
        }
        details["inputs"].append(input_info)
    
    # Look for <select> tags (dropdown menus)
    for select in form.find_all("select"):
        input_info = {
            "name": select.get("name"),
            "type": "select",
            "value": ""  # We'll use empty for dropdowns
        }
        details["inputs"].append(input_info)
    
    return details


def should_test_this_field(input_field):
    """
    Decide if we should test this field or skip it.
    
    We SKIP:
    - Submit buttons (they just send the form)
    - CSRF tokens (security tokens that we need to keep)
    
    We TEST:
    - Text boxes (where users type stuff)
    - Hidden fields (sneaky fields that might be vulnerable!)
    """
    name = input_field.get("name")
    field_type = input_field.get("type", "text").lower()
    
    # Skip if there's no name
    if not name:
        return False
    
    name_lower = name.lower()
    
    # Skip CSRF tokens (we need these to work!)
    skip_names = ["token", "csrf", "user_token", "_token"]
    for skip in skip_names:
        if skip in name_lower:
            return False
    
    # Skip buttons (they don't hold data)
    skip_types = ["submit", "button", "image", "reset"]
    if field_type in skip_types:
        return False
    
    # Test everything else!
    return True


def build_target_url(page_url, form_action):
    """
    Figure out where to send the form.
    
    Forms can have:
    - No action (send to same page)
    - "#" (send to same page)  
    - "/login" (send to /login on same site)
    - "http://..." (send to specific URL)
    """
    # No action or "#" means same page
    if not form_action or form_action == "#":
        return page_url
    
    # Full URL starting with http
    if form_action.startswith("http"):
        return form_action
    
    # Relative URL - add to current page's base
    if page_url.endswith("/"):
        return page_url + form_action
    else:
        # Remove the last part of URL and add action
        base = page_url.rsplit("/", 1)[0]
        return base + "/" + form_action


def test_form_field(session, url, form_details, field_name, payload):
    """
    Test ONE field in a form with a payload.
    
    How it works:
    1. Fill in all fields with their normal values
    2. Put the PAYLOAD in the field we're testing
    3. Submit the form
    4. Return the response
    
    Example:
        Normal:  username="admin", password="1234"
        Testing: username="admin", password="' OR 1=1--"
                                            ↑ payload here!
    """
    # Build the data to send
    form_data = {}
    
    for field in form_details["inputs"]:
        name = field.get("name")
        if not name:
            continue
            
        if name == field_name:
            # This is the field we're testing - use payload!
            form_data[name] = payload
        else:
            # Other fields - use their normal value
            form_data[name] = field.get("value", "")
    
    # Where do we send it?
    target_url = build_target_url(url, form_details["action"])
    
    # Send the form (with rate limiting!)
    if form_details["method"] == "POST":
        response = rate_limited_request(session, "POST", target_url, data=form_data)
    else:
        response = rate_limited_request(session, "GET", target_url, params=form_data)
    
    return response


def scan_forms_for_sqli(session, url):
    """
    Scan all forms on a page for SQL Injection.
    
    Returns a list of vulnerable fields found.
    """
    print(f"\n[*] Looking for forms on: {url}")
    
    # SQL error messages that mean it's vulnerable
    sql_errors = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "oracle",
        "syntax error"
    ]
    
    results = []
    
    # Step 1: Get all forms on the page
    forms = get_forms(session, url)
    print(f"[*] Found {len(forms)} form(s)")
    
    # Step 2: Test each form
    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        print(f"\n[*] Testing Form #{i+1} ({form_details['method']})")
        
        # Step 3: Test each field in the form
        for field in form_details["inputs"]:
            if not should_test_this_field(field):
                continue
            
            field_name = field["name"]
            print(f"    Testing field: {field_name}")
            
            # Send a single quote - this breaks SQL!
            payload = "'"
            response = test_form_field(session, url, form_details, field_name, payload)
            
            # Check if we see SQL errors
            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower:
                    print(f"    [+] VULNERABLE! SQL Injection in '{field_name}'")
                    results.append({
                        "field": field_name,
                        "type": "SQL Injection",
                        "form_method": form_details["method"]
                    })
                    break
    
    return results


def scan_forms_for_xss(session, url):
    """
    Scan all forms on a page for XSS (Cross-Site Scripting).
    
    Returns a list of vulnerable fields found.
    """
    print(f"\n[*] Looking for forms on: {url}")
    
    results = []
    
    # Our XSS payload - if this appears in response, it's vulnerable!
    xss_payload = "<script>alert('XSS')</script>"
    
    # Step 1: Get all forms
    forms = get_forms(session, url)
    print(f"[*] Found {len(forms)} form(s)")
    
    # Step 2: Test each form
    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        print(f"\n[*] Testing Form #{i+1} ({form_details['method']})")
        
        # Step 3: Test each field
        for field in form_details["inputs"]:
            if not should_test_this_field(field):
                continue
            
            field_name = field["name"]
            print(f"    Testing field: {field_name}")
            
            response = test_form_field(session, url, form_details, field_name, xss_payload)
            
            # If our script appears unchanged, it's vulnerable!
            if xss_payload in response.text:
                print(f"    [+] VULNERABLE! XSS in '{field_name}'")
                results.append({
                    "field": field_name,
                    "type": "XSS",
                    "form_method": form_details["method"]
                })
    
    return results
