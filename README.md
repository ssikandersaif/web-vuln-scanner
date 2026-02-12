# Web Vulnerability Scanner

A Python-based automated security scanner that detects common web vulnerabilities following the OWASP Top 10 framework. Built for educational purposes and security testing in controlled environments.

## Features

- **SQL Injection (SQLi)** - Detects database query vulnerabilities
- **Cross-Site Scripting (XSS)** - Identifies reflected XSS flaws
- **Command Injection (CMDi)** - Finds OS command execution vulnerabilities
- **Path Traversal** - Detects directory traversal/file inclusion issues
- **Automatic Form Discovery** - Crawls and tests all forms on target pages
- **Multi-Application Support** - Works with DVWA, Juice Shop, bWAPP, Mutillidae, and generic web apps
- **Professional Reporting** - Generates detailed reports with OWASP mappings and remediation guidance
- **Rate Limiting** - Prevents overwhelming target servers
- **Confidence Scoring** - Reduces false positives with verification mechanisms

## Installation

```bash
# Clone the repository
git clone https://github.com/ssikandersaif/web-vuln-scanner.git
cd web-vuln-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python main.py --target http://localhost:8080

# Scan specific vulnerabilities only
python main.py --target http://localhost:8080 --modules sqli,xss

# Scan with authentication
python main.py --target http://localhost:8080 --auth admin:password

# Target specific applications
python main.py --target http://localhost:8080 --app dvwa --security low

# Skip form scanning
python main.py --target http://localhost:8080 --no-forms

# View all options
python main.py --help
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Target URL (required) | - |
| `--app` | Application type (dvwa, juiceshop, bwapp, mutillidae, generic) | dvwa |
| `--auth` | Credentials as username:password | admin:password |
| `--modules` | Vulnerabilities to test (sqli,xss,cmdi,traversal,forms) | all |
| `--security` | DVWA security level (low, medium, high, impossible) | low |
| `--output` | Custom output report filename | auto-generated |
| `--no-forms` | Skip automatic form scanning | False |

## Output

The scanner generates:
1. **Console Output** - Real-time scan progress and findings
2. **Report File** - Detailed text report in the project directory
3. **Log Files** - Complete scan logs in the `logs/` directory

## Project Structure

```
web-vuln-scanner/
├── main.py                 # Entry point, CLI interface
├── requirements.txt        # Python dependencies
├── MULTI_APP_GUIDE.md      # Multi-app usage guide
├── PROJECT_MAP.md          # Project documentation
├── auth/                   # Authentication handlers
│   └── session_handler.py
├── scanner/                # Vulnerability testing modules
│   ├── sqli.py            # SQL Injection tests
│   ├── xss.py             # XSS tests
│   ├── cmdi.py            # Command Injection tests
│   ├── traversal.py       # Path Traversal tests
│   └── form_scanner.py    # Form discovery and testing
├── report/                 # Report generation
│   └── report_generator.py
├── utils/                  # Utility functions
│   ├── loggers.py
│   ├── rate_limiter.py
│   └── vuln_definitions.py
└── logs/                   # Generated log files (runtime)
```

## How It Works

1. **Session Creation** - Establishes authenticated session with target
2. **Payload Injection** - Tests each input with vulnerability-specific payloads
3. **Response Analysis** - Analyzes responses for vulnerability indicators
4. **Verification** - Confirms findings to reduce false positives
5. **Report Generation** - Creates comprehensive security report with remediation steps

## Technologies Used

- **Python 3** - Core programming language
- **Requests** - HTTP library for web requests
- **BeautifulSoup4** - HTML parsing and form discovery
- **Argparse** - Command-line interface
- **Built-in Logging** - Comprehensive activity logging

## Testing Targets

This scanner is designed to work with intentionally vulnerable web applications:
- [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA)
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- [bWAPP](http://www.itsecgames.com/)
- [Mutillidae](https://github.com/webpwnized/mutillidae)

## Disclaimer

**⚠️ IMPORTANT:** This tool is for educational and authorized testing purposes only.

- Only scan applications you own or have explicit permission to test
- Unauthorized scanning of websites is illegal and unethical
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

## Author

Syed Saif Sikander - Internship Project

## License

This project is provided for educational purposes. Use responsibly and ethically.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to improve the scanner.
