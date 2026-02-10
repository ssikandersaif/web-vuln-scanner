# Testing Multiple Vulnerable Applications

Your scanner now supports multiple vulnerable web applications!

## Supported Applications

### 1. DVWA (Damn Vulnerable Web Application)
```bash
# Start DVWA
docker run -p 8080:80 vulnerables/web-dvwa

# Scan
python main.py --target http://localhost:8080 --app dvwa --auth admin:password
```

**Works:** ✅ All vulnerabilities (SQLi, XSS, CMDi, Traversal, Forms)

---

### 2. OWASP Juice Shop
```bash
# Start Juice Shop
docker run -p 3000:3000 bkimminich/juice-shop

# First, register an account at http://localhost:3000 or use SQLi to login

# Scan (skip forms as Juice Shop uses REST API)
python main.py --target http://localhost:3000 --app juiceshop --auth "admin@juice-sh.op:admin123" --no-forms
```

**Works:** ✅ SQLi (limited), ✅ XSS, ✅ Path Traversal  
**Note:** Juice Shop uses REST APIs, so form scanner won't find much

---

### 3. bWAPP (buggy Web Application)
```bash
# Start bWAPP
docker run -p 8081:80 raesene/bwapp

# Scan
python main.py --target http://localhost:8081/bWAPP --app bwapp --auth bee:bug
```

**Works:** ✅ All vulnerabilities (similar to DVWA)

---

### 4. Mutillidae (on Metasploitable 2)
```bash
# Assuming Metasploitable 2 is running at 192.168.1.100

# Scan
python main.py --target http://192.168.1.100/mutillidae --app mutillidae --auth admin:admin
```

**Works:** ✅ Most vulnerabilities  
**Note:** Mutillidae has different page structure, may need custom test URLs

---

### 5. Generic Mode (No Authentication)
```bash
# For any web app without authentication
python main.py --target http://example.com --app generic --no-forms
```

**Use when:** Testing public pages or apps with unknown auth

---

## Compatibility Matrix

| App | SQLi | XSS | CMDi | Traversal | Forms | Auth Support |
|-----|------|-----|------|-----------|-------|--------------|
| **DVWA** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full |
| **Juice Shop** | ⚠️ | ✅ | ❌ | ✅ | ⚠️ | ✅ JWT |
| **bWAPP** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full |
| **Mutillidae** | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ Full |
| **Generic** | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ None |

**Legend:**
- ✅ = Fully supported
- ⚠️ = Partial support (may need adjustments)
- ❌ = Not applicable

---

## Limitations

### Juice Shop
- Uses REST API (JSON), not HTML forms
- Most vulnerabilities are in API endpoints, not traditional forms
- Need to adjust test URLs for API endpoints
- Example: `/rest/products/search?q=<xss>`

### Metasploitable 2
- Contains multiple apps, each needs different config
- Network access required (VM setup)
- Some apps use different auth mechanisms

### bWAPP
- Has 100+ vulnerability scenarios
- You may need to navigate to specific pages
- Example: `http://localhost:8081/bWAPP/sqli_1.php`

---

## Tips

### Testing Juice Shop Properly
```bash
# 1. Skip forms (it uses APIs)
python main.py --target http://localhost:3000 --app juiceshop --no-forms

# 2. Test specific API endpoints manually
# Add these URLs to your VULNERABILITY_TESTS in main.py:
# - /rest/products/search
# - /api/Users
# - /ftp (for path traversal)
```

### Testing bWAPP
```bash
# bWAPP has a chooser page, you may want to test specific pages:
python main.py --target http://localhost:8081/bWAPP --app bwapp --modules sqli
```

### Testing Mutillidae
```bash
# Best with Metasploitable 2 VM
python main.py --target http://192.168.1.100/mutillidae --app mutillidae
```

---

## Quick Test All Apps

```bash
# Test DVWA
python main.py --target http://localhost:8080 --app dvwa

# Test bWAPP
python main.py --target http://localhost:8081/bWAPP --app bwapp --auth bee:bug

# Test Juice Shop (basic)
python main.py --target http://localhost:3000 --app juiceshop --no-forms --modules xss
```

---

## Need Custom Configuration?

Edit `auth/session_handler.py` to add your own login function, or use `--app generic` to skip authentication entirely.
