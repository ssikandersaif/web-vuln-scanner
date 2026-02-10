#!/usr/bin/env python3
"""
Web Vulnerability Scanner
=========================
A professional vulnerability scanner for web applications.

Usage:
    python main.py --target http://localhost:8080 --auth admin:password
    python main.py --target http://localhost:8080 --modules sqli,xss
    python main.py --help

Author: [Your Name]
For: Internship Project
"""

import argparse
import time
import os
import json
import requests
from datetime import timedelta, datetime

# Authentication
from auth.session_handler import (
    create_session, login_dvwa, set_dvwa_security,
    login_juice_shop, login_bwapp, login_mutillidae
)

# Scanners
from scanner.sqli import test_sqli
from scanner.xss import test_xss
from scanner.cmdi import test_cmdi
from scanner.traversal import test_traversal
from scanner.form_scanner import scan_forms_for_sqli, scan_forms_for_xss

# Utilities
from utils.rate_limiter import default_limiter
from utils.vuln_definitions import get_vuln_info, get_owasp_info
from report.report_generator import ReportGenerator
from utils.loggers import setup_logger, log_scan_start, log_scan_end, log_vulnerability_found, log_test_start, log_error


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Professional Web Vulnerability Scanner",
        epilog="Example: python main.py --target http://localhost:8080 --auth admin:password",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://localhost:8080)"
    )
    
    parser.add_argument(
        "--app",
        choices=["dvwa", "juiceshop", "bwapp", "mutillidae", "generic"],
        default="dvwa",
        help="Target application type (default: dvwa)"
    )
    
    parser.add_argument(
        "--auth",
        help="Authentication credentials in format username:password (default: admin:password)",
        default="admin:password"
    )
    
    parser.add_argument(
        "--modules",
        help="Comma-separated list: sqli,xss,cmdi,traversal,forms or 'all' (default: all)",
        default="all"
    )
    
    parser.add_argument(
        "--security",
        choices=["low", "medium", "high", "impossible"],
        default="low",
        help="DVWA security level (default: low)"
    )
    
    parser.add_argument(
        "--output",
        help="Output report file (default: auto-generated)",
        default=None
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    
    parser.add_argument(
        "--no-forms",
        action="store_true",
        help="Skip automatic form scanning"
    )
    
    return parser.parse_args()


# ============================================================
# VULNERABILITY TESTS
# ============================================================

# DVWA test configuration
DVWA_TESTS = [
    {
        "name": "SQL Injection",
        "module": "sqli",
        "url": "/vulnerabilities/sqli/",
        "param": "id",
        "function": test_sqli,
        "vuln_type": "sqli"
    },
    {
        "name": "Reflected XSS",
        "module": "xss",
        "url": "/vulnerabilities/xss_r/",
        "param": "name",
        "function": test_xss,
        "vuln_type": "xss"
    },
    {
        "name": "Command Injection",
        "module": "cmdi",
        "url": "/vulnerabilities/exec/",
        "param": "ip",
        "function": test_cmdi,
        "vuln_type": "cmdi"
    },
    {
        "name": "Path Traversal",
        "module": "traversal",
        "url": "/vulnerabilities/fi/",
        "param": "page",
        "function": test_traversal,
        "vuln_type": "traversal"
    },
]

# Juice Shop test configuration
JUICESHOP_TESTS = [
    {
        "name": "SQL Injection (Product Search)",
        "module": "sqli",
        "url": "/rest/products/search",
        "param": "q",
        "function": test_sqli,
        "vuln_type": "sqli"
    },
    {
        "name": "XSS (Search via DOM)",
        "module": "xss",
        "url": "/#/search",
        "param": "q",
        "function": test_xss,
        "vuln_type": "xss"
    },
    {
        "name": "Path Traversal (FTP - Null Byte)",
        "module": "traversal",
        "url": "/ftp/package.json.bak",
        "param": "file",
        "function": test_traversal,
        "vuln_type": "traversal"
    },
]

# bWAPP test configuration
BWAPP_TESTS = [
    {
        "name": "SQL Injection",
        "module": "sqli",
        "url": "/sqli_1.php",
        "param": "title",
        "function": test_sqli,
        "vuln_type": "sqli"
    },
    {
        "name": "Reflected XSS",
        "module": "xss",
        "url": "/xss_get.php",
        "param": "firstname",
        "function": test_xss,
        "vuln_type": "xss"
    },
    {
        "name": "Command Injection",
        "module": "cmdi",
        "url": "/commandi.php",
        "param": "target",
        "function": test_cmdi,
        "vuln_type": "cmdi"
    },
    {
        "name": "Path Traversal",
        "module": "traversal",
        "url": "/directory_traversal_1.php",
        "param": "page",
        "function": test_traversal,
        "vuln_type": "traversal"
    },
]

# Mutillidae test configuration
MUTILLIDAE_TESTS = [
    {
        "name": "SQL Injection",
        "module": "sqli",
        "url": "/index.php?page=user-info.php",
        "param": "username",
        "function": test_sqli,
        "vuln_type": "sqli"
    },
    {
        "name": "Reflected XSS",
        "module": "xss",
        "url": "/index.php?page=dns-lookup.php",
        "param": "target_host",
        "function": test_xss,
        "vuln_type": "xss"
    },
    {
        "name": "Command Injection",
        "module": "cmdi",
        "url": "/index.php?page=dns-lookup.php",
        "param": "target_host",
        "function": test_cmdi,
        "vuln_type": "cmdi"
    },
    {
        "name": "Path Traversal",
        "module": "traversal",
        "url": "/index.php",
        "param": "page",
        "function": test_traversal,
        "vuln_type": "traversal"
    },
]

# Default tests for generic mode
GENERIC_TESTS = []


# ============================================================
# MAIN SCANNER FUNCTION
# ============================================================

def run_scanner(args):
    """Main scanning function."""
    
    # Setup logging
    logger = setup_logger(log_to_file=True)
    
    start_time = time.time()
    
    # Parse auth credentials
    if ":" in args.auth:
        username, password = args.auth.split(":", 1)
    else:
        username, password = "admin", "password"
    
    # Determine which modules to run
    if args.modules.lower() == "all":
        enabled_modules = ["sqli", "xss", "cmdi", "traversal", "forms"]
    else:
        enabled_modules = [m.strip() for m in args.modules.split(",")]
    
    # Log scan start
    log_scan_start(args.target, enabled_modules)
    
    # Create report generator
    report = ReportGenerator(args.target)
    
    # Banner
    print("=" * 80)
    print("                    WEB VULNERABILITY SCANNER")
    print("=" * 80)
    print(f"  Target: {args.target}")
    print(f"  Security Level: {args.security}")
    print(f"  Modules: {', '.join(enabled_modules)}")
    print("=" * 80)
    print()
    
    # Step 0: Verify target is reachable
    print("[*] Verifying target is reachable...")
    session = create_session()
    try:
        response = session.get(args.target, timeout=5)
        print(f"[+] Target is UP (Status: {response.status_code})")
        if response.status_code == 404:
            print("[!] Warning: Got 404 - URL might be incorrect")
    except requests.exceptions.ConnectionError:
        print(f"[!] ERROR: Cannot connect to {args.target}")
        print("[!] Make sure the service is running and the URL is correct")
        return
    except requests.exceptions.Timeout:
        print(f"[!] ERROR: Connection timeout to {args.target}")
        return
    except Exception as e:
        print(f"[!] ERROR: {str(e)}")
        return
    
    # Step 1: Create session and login
    print("[*] Creating session...")
    logger.info("Creating session")
    
    session = create_session()
    
    # Parse username and password
    username, password = args.auth.split(":")
    
    # Login based on app type
    print(f"[*] Logging in as '{username}'...")
    logger.info(f"Logging in as '{username}' to {args.app}")
    
    # Choose login method based on app type
    if args.app == "dvwa":
        login_success = login_dvwa(session, args.target, username, password)
        if login_success:
            set_dvwa_security(session, args.target, args.security)
    elif args.app == "juiceshop":
        # For Juice Shop REST API, authentication is optional for testing
        # Most vulnerable endpoints like /rest/products/search don't require auth
        print("[*] Juice Shop mode - REST API endpoints don't require authentication")
        login_success = True
    elif args.app == "bwapp":
        login_success = login_bwapp(session, args.target, username, password)
    elif args.app == "mutillidae":
        login_success = login_mutillidae(session, args.target, username, password)
    else:
        # Generic - no login, just scan
        print("[*] Generic mode - skipping authentication")
        login_success = True
    
    if not login_success:
        print(f"[!] Login to {args.app} failed.")
        log_error("Login failed")
        return
    
    print()
    print("[*] Starting vulnerability scan...")
    print("-" * 80)
    
    # Step 2: Select appropriate test configuration based on app type
    if args.app == "dvwa":
        VULNERABILITY_TESTS = DVWA_TESTS
    elif args.app == "juiceshop":
        VULNERABILITY_TESTS = JUICESHOP_TESTS
    elif args.app == "bwapp":
        VULNERABILITY_TESTS = BWAPP_TESTS
    elif args.app == "mutillidae":
        VULNERABILITY_TESTS = MUTILLIDAE_TESTS
    else:
        VULNERABILITY_TESTS = GENERIC_TESTS
    
    # Step 3: Run vulnerability tests
    for test in VULNERABILITY_TESTS:
        # Check if this module is enabled
        if test["module"] not in enabled_modules:
            continue
        
        name = test["name"]
        url = args.target + test["url"]
        param = test["param"]
        scan_function = test["function"]
        vuln_type = test["vuln_type"]
        
        vuln_info = get_vuln_info(vuln_type)
        owasp_id = vuln_info.get("owasp", "N/A")
        
        print(f"\n[*] Testing: {name}")
        print(f"    URL: {url}")
        print(f"    Parameter: {param}")
        print(f"    OWASP: {owasp_id} - {get_owasp_info(owasp_id).get('name', 'Unknown')}")
        
        log_test_start(name, url, param)
        
        try:
            result = scan_function(session, url, param, base_url=args.target)
            
            # Handle both dict and bool return types
            if isinstance(result, dict):
                is_vulnerable = result.get("vulnerable", False)
                confidence = result.get("confidence", "NONE")
                evidence = result.get("evidence", "")
                payload = result.get("payload", "")
            else:
                is_vulnerable = result
                confidence = "HIGH" if result else "NONE"
                evidence = ""
                payload = ""
            
            if is_vulnerable:
                conf_symbols = {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}
                conf_symbol = conf_symbols.get(confidence, "[?]")
                print(f"    [+] VULNERABLE! {conf_symbol}")
                print(f"    [+] Evidence: {evidence}")
                
                log_vulnerability_found(name, url, param, confidence)
                report.add_finding(vuln_type, url, param, confidence, evidence, payload)
            else:
                print(f"    [-] Not vulnerable")
                
        except Exception as e:
            print(f"    [!] Error during scan: {e}")
            log_error(f"Error testing {name}", e)
    
    # Step 3: Form scanning
    if "forms" in enabled_modules and not args.no_forms:
        print()
        print("=" * 80)
        print("  FORM SCANNING (Automatic)")
        print("=" * 80)
        
        pages_to_scan = [
            "/vulnerabilities/sqli/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
        ]
        
        for page in pages_to_scan:
            full_url = args.target + page
            
            if "sqli" in enabled_modules:
                sqli_results = scan_forms_for_sqli(session, full_url)
                for result in sqli_results:
                    report.add_finding("sqli", full_url, result["field"], "HIGH", f"Form field vulnerable", "")
            
            if "xss" in enabled_modules:
                xss_results = scan_forms_for_xss(session, full_url)
                for result in xss_results:
                    report.add_finding("xss", full_url, result["field"], "HIGH", f"Form field vulnerable", "")
    
    # Step 4: Generate report
    end_time = time.time()
    duration = str(timedelta(seconds=int(end_time - start_time)))
    
    stats = default_limiter.get_stats()
    stats["duration"] = duration
    report.set_stats(stats)
    
    # Save report
    if args.output:
        filename = args.output
    else:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    report.save_to_file(filename)
    print()
    print(f"[*] Report saved to: {filename}")
    
    # Print report to console
    print()
    print(report.generate_console_report())
    
    # Log scan end
    log_scan_end(len(report.findings), duration)
    
    print()
    print("=" * 80)
    print(f"  Scan completed in {duration}")
    print(f"  {report.generate_summary()}")
    print("=" * 80)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    args = parse_arguments()
    run_scanner(args)
