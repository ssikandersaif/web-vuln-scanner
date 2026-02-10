"""
Logging System
==============

Creates logs for debugging and tracking what the scanner does.

Think of this like a diary that writes down everything the scanner does:
- What pages it visits
- What vulnerabilities it finds
- Any errors that happen

This helps you debug problems and review what happened later!
"""

import logging
import os
from datetime import datetime


def setup_logger(log_to_file=True, log_level=logging.INFO):
    """
    Set up the logging system.
    
    Args:
        log_to_file: Whether to save logs to a file
        log_level: How detailed to be (DEBUG, INFO, WARNING, ERROR)
    
    Returns:
        A logger object you can use to write logs
    """
    
    # Create logger
    logger = logging.getLogger("WebVulnScanner")
    logger.setLevel(log_level)
    
    # Remove existing handlers (in case we call this twice)
    logger.handlers = []
    
    # Create formatter (what each log line looks like)
    # Example: 2026-02-01 14:30:45 - INFO - Starting scan...
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler (prints to screen)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Only show warnings and errors on screen
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (saves to file)
    if log_to_file:
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Create a log file with current date/time
        log_filename = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_filename)
        file_handler.setLevel(log_level)  # Save everything to file
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        logger.info(f"Logging to file: {log_filename}")
    
    return logger


# Create a default logger that everyone can use
logger = setup_logger()


def log_scan_start(target, modules):
    """Log when a scan starts."""
    logger.info("=" * 60)
    logger.info("SCAN STARTED")
    logger.info(f"Target: {target}")
    logger.info(f"Modules: {', '.join(modules)}")
    logger.info("=" * 60)


def log_scan_end(total_vulns, duration):
    """Log when a scan ends."""
    logger.info("=" * 60)
    logger.info("SCAN COMPLETED")
    logger.info(f"Total vulnerabilities found: {total_vulns}")
    logger.info(f"Scan duration: {duration}")
    logger.info("=" * 60)


def log_vulnerability_found(vuln_name, url, param, confidence):
    """Log when a vulnerability is found."""
    logger.info(f"[VULN] {vuln_name} found at {url} (param: {param}, confidence: {confidence})")


def log_test_start(test_name, url, param):
    """Log when starting a test."""
    logger.info(f"[TEST] Testing {test_name} on {url} (param: {param})")


def log_error(message, exception=None):
    """Log an error."""
    if exception:
        logger.error(f"{message}: {str(exception)}", exc_info=True)
    else:
        logger.error(message)


def log_request(method, url):
    """Log an HTTP request."""
    logger.debug(f"[REQUEST] {method} {url}")


def log_response(status_code, length):
    """Log an HTTP response."""
    logger.debug(f"[RESPONSE] Status: {status_code}, Length: {length} bytes")
