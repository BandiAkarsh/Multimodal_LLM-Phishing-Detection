# Comprehensive Security Audit Report
## Phishing Detection Projects

**Audit Date:** February 19, 2026  
**Auditor:** SecurityEngineer (AI Security Specialist)  
**Projects Audited:**
1. phishing_detection_project (FastAPI)
2. phishing-guard-daemon (Custom HTTP Server)
3. Browser Extensions (Both projects)

---

## Executive Summary

This audit identified **23 security issues** across three projects:
- **3 Critical** severity issues
- **10 High** severity issues  
- **8 Medium** severity issues
- **2 Low** severity issues

**Key Findings:**
1. Authentication bypass vulnerability in FastAPI login endpoint
2. No HTTPS enforcement in daemon project
3. Hardcoded credentials in browser extensions
4. Missing SSRF protection in some endpoints
5. Insecure CORS configurations

---

## CRITICAL SEVERITY ISSUES

### C1: Authentication Bypass - FastAPI Login Accepts ANY Credentials
**Location:** `phishing_detection_project/04_inference/api.py` (lines 191-228)

**Issue:**
The `/auth/login` endpoint generates JWT tokens for ANY username/password combination without validation:

```python
@app.post("/auth/login")
async def login(credentials: dict):
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    
    # Only checks if fields exist, not if they're valid!
    if not username or not password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
    # Generates token for ANY credentials
    token = auth_manager.create_token(username)
```

**Impact:**
- Anyone can authenticate and access protected endpoints
- Rate limiting bypass via token generation
- Complete authentication bypass

**Remediation:**
```python
# Implement proper credential validation
VALID_USERS = {
    "admin": os.getenv("ADMIN_PASSWORD_HASH")  # Use bcrypt hashed passwords
}

@app.post("/auth/login")
async def login(credentials: dict):
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    
    # Validate against stored credentials
    if username not in VALID_USERS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Use bcrypt for password verification
    if not bcrypt.checkpw(password.encode(), VALID_USERS[username]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = auth_manager.create_token(username)
    return {"access_token": token, "token_type": "bearer"}
```

---

### C2: Hardcoded Credentials in Browser Extensions
**Location:** Both browser-extension/background.js files (lines 35-36)

**Issue:**
```javascript
body: JSON.stringify({
    username: 'browser-extension',
    password: 'extension-token-' + chrome.runtime.id
})
```

**Impact:**
- Predictable password pattern
- Extension ID can be extracted from extension
- Authentication bypass if server accepts any credentials (see C1)

**Remediation:**
```javascript
// Use secure token exchange or device flow
// Option 1: PKCE flow for extensions
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Option 2: Pre-registered extension tokens
const response = await fetch(`${API_BASE}/auth/extension`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-Extension-ID': chrome.runtime.id,
        'X-Extension-Signature': generateHMAC(chrome.runtime.id, SECRET_KEY)
    }
});
```

---

### C3: No HTTPS in Daemon Project
**Location:** `phishing-guard-daemon/src/api_server.py`

**Issue:**
The custom HTTP server only supports HTTP, not HTTPS. Authentication tokens and analysis results are transmitted in plaintext.

**Impact:**
- Token interception via network sniffing
- Man-in-the-middle attacks
- Credential theft

**Remediation:**
```python
# Add TLS support to HTTPServer
import ssl

def run_server(host='127.0.0.1', port=8000, ssl_cert=None, ssl_key=None):
    server = HTTPServer((host, port), PhishingGuardHandler)
    
    if ssl_cert and ssl_key:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(ssl_cert, ssl_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    
    server.serve_forever()
```

---

## HIGH SEVERITY ISSUES

### H1: CORS Misconfiguration - Wildcard with Credentials
**Location:** `phishing-guard-daemon/src/api_server.py` (line 88)

**Issue:**
```python
self.send_header('Access-Control-Allow-Origin', '*')
```

Combined with authentication, this allows any website to make authenticated requests.

**Remediation:**
```python
ALLOWED_ORIGINS = ['http://localhost:8000', 'chrome-extension://*']

if origin in ALLOWED_ORIGINS:
    self.send_header('Access-Control-Allow-Origin', origin)
    self.send_header('Access-Control-Allow-Credentials', 'true')
```

---

### H2: Insecure Token Storage in Browser
**Location:** Both browser extensions

**Issue:**
```javascript
chrome.storage.local.set({authToken: data.access_token});
```

Tokens stored in localStorage/sync storage are:
- Accessible to any script with storage permission
- Not encrypted at rest
- Persisted to disk in plaintext

**Remediation:**
```javascript
// Use chrome.storage.session (Memory-only, cleared when browser closes)
chrome.storage.session.set({authToken: data.access_token});

// Or implement token refresh with short-lived tokens
// And use httpOnly cookies where possible
```

---

### H3: Missing Request Size Limits
**Location:** `phishing-guard-daemon/src/api_server.py` (line 151)

**Issue:**
```python
content_length = int(self.headers.get('Content-Length', 0))
body = self.rfile.read(content_length).decode()
```

No maximum content length check. Can lead to:
- Memory exhaustion
- DoS attacks

**Remediation:**
```python
MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB

content_length = int(self.headers.get('Content-Length', 0))
if content_length > MAX_CONTENT_LENGTH:
    self.send_json({'error': 'Request too large'}, 413)
    return
```

---

### H4: Weak SSL Certificate Generation
**Location:** `phishing_detection_project/04_inference/api.py` (lines 506-509)

**Issue:**
```python
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # Should be 4096
)
```

**Remediation:**
```python
key_size=4096  # Minimum for production
```

---

### H5: No Certificate Validation for API Calls
**Location:** Browser extensions

**Issue:**
Extensions make fetch calls to localhost without certificate validation.

**Remediation:**
```javascript
// For production, implement certificate pinning
const EXPECTED_CERT_FINGERPRINT = 'SHA256:...';

// Or use native messaging for secure communication
// between extension and native host
```

---

### H6: Trust Boundary Violation - Localhost Bypass
**Location:** `phishing-guard-daemon/src/api_server.py` (lines 179-182)

**Issue:**
```python
if client_ip not in ['127.0.0.1', 'localhost', '::1']:
    self.send_json({'error': 'Unauthorized'}, 401)
    return
```

Localhost bypass without additional authentication allows:
- Any local process to access the API
- Malware running on the machine to exploit the API

**Remediation:**
```python
# Require authentication even from localhost
# Or use Unix domain sockets with proper permissions
```

---

### H7: Missing Security Headers in Daemon
**Location:** `phishing-guard-daemon/src/api_server.py`

**Issue:**
No security headers (HSTS, CSP, X-Frame-Options, etc.)

**Remediation:**
```python
def send_json(self, data: dict, status: int = 200):
    self.send_response(status)
    self.send_header('Content-Type', 'application/json')
    self.send_header('X-Content-Type-Options', 'nosniff')
    self.send_header('X-Frame-Options', 'DENY')
    self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    self.send_header('Content-Security-Policy', "default-src 'self'")
    self.end_headers()
    self.wfile.write(json.dumps(data).encode())
```

---

### H8: Insecure File Permissions for PID File
**Location:** `phishing-guard-daemon/src/daemon.py` (line 31)

**Issue:**
```python
PID_FILE = Path('/tmp/phishing-guard-daemon.pid')
```

/tmp is world-writable. Attackers can:
- Create fake PID files
- Cause denial of service
- Potential privilege escalation

**Remediation:**
```python
# Use /run/user/<uid>/ for user services
import getpass
PID_FILE = Path(f'/run/user/{os.getuid()}/phishing-guard-daemon.pid')

# Or create with restricted permissions
PID_FILE.write_text(str(os.getpid()))
os.chmod(PID_FILE, 0o600)
```

---

### H9: SQL Injection Risk in Web Scraper (Mitigated but Pattern Exists)
**Location:** `phishing_detection_project/05_utils/web_scraper.py`

**Issue:**
While no direct SQL queries exist, the toolkit detection uses regex patterns that could be bypassed.

**Remediation:**
Already mitigated by SSRF validator, but ensure all user input is sanitized before any database operations.

---

### H10: Information Disclosure in Error Messages
**Location:** Multiple files

**Issue:**
```python
except Exception as e:
    raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
```

Error messages expose internal details to clients.

**Remediation:**
```python
import logging
logger = logging.getLogger(__name__)

try:
    result = await phishing_service.analyze_url_async(...)
except Exception as e:
    logger.error(f"Analysis failed: {str(e)}", exc_info=True)
    raise HTTPException(status_code=500, detail="Internal server error")
```

---

## MEDIUM SEVERITY ISSUES

### M1: Logging of Sensitive Data
**Location:** `phishing_detection_project/04_inference/api.py` (line 340)

**Issue:**
```python
print(f"[AUDIT] User {user.get('sub')} scanned URL: {request.url}")
```

URLs may contain sensitive parameters (tokens, PII).

**Remediation:**
```python
from urllib.parse import urlparse, urlunparse

def sanitize_url(url: str) -> str:
    parsed = urlparse(url)
    # Remove query parameters for logging
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

print(f"[AUDIT] User {user.get('sub')} scanned URL: {sanitize_url(request.url)}")
```

---

### M2: Deprecated Security Header
**Location:** `phishing_detection_project/04_inference/api.py` (line 152)

**Issue:**
```python
response.headers["X-XSS-Protection"] = "1; mode=block"
```

This header is deprecated and can introduce vulnerabilities.

**Remediation:**
Remove this header; use CSP instead.

---

### M3: In-Memory Rate Limiting Not Production-Ready
**Location:** `phishing_detection_project/04_inference/auth.py` (lines 307-446)

**Issue:**
Rate limiting uses in-memory storage which doesn't work with:
- Multiple workers/processes
- Container orchestration
- Server restarts

**Remediation:**
Already supports Redis; ensure REDIS_URL is set in production.

---

### M4: No Input Validation on Schemas
**Location:** `phishing_detection_project/04_inference/schemas.py`

**Issue:**
URL fields accept any string without format validation beyond Pydantic defaults.

**Remediation:**
```python
from pydantic import BaseModel, HttpUrl, validator

class URLAnalysisRequest(BaseModel):
    url: HttpUrl  # Use HttpUrl type for validation
    
    @validator('url')
    def validate_url_not_private(cls, v):
        # Additional validation logic
        return v
```

---

### M5: Potential Regex DoS (ReDoS)
**Location:** `phishing_detection_project/05_utils/web_scraper.py` (lines 91-97)

**Issue:**
Complex regex patterns in ToolkitSignatureDetector could be exploited with malicious input.

**Remediation:**
```python
import re

# Add timeout to regex operations
def safe_search(pattern, string, timeout=1.0):
    # Use signal or threading for timeout
    return re.search(pattern, string)
```

---

### M6: No Certificate Pinning for External APIs
**Location:** `phishing_detection_project/05_utils/connectivity.py`

**Issue:**
External connectivity checks don't validate certificate fingerprints.

**Remediation:**
```python
import ssl
import certifi

context = ssl.create_default_context(cafile=certifi.where())
```

---

### M7: Dependency Version Constraints
**Location:** All requirements.txt files

**Issue:**
```
requests>=2.31.0
```

No upper bound on versions could introduce breaking changes or vulnerabilities.

**Remediation:**
```
requests>=2.31.0,<3.0.0
```

---

### M8: Potential Race Condition in API Key Storage
**Location:** `phishing_detection_project/04_inference/auth.py` (lines 245-251)

**Issue:**
```python
def _save_api_keys(self):
    with open(API_KEYS_FILE, "w") as f:
        json.dump(self.api_keys, f, indent=2)
    os.chmod(API_KEYS_FILE, 0o600)
```

No file locking; concurrent writes could corrupt the file.

**Remediation:**
```python
import fcntl

def _save_api_keys(self):
    with open(API_KEYS_FILE, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            json.dump(self.api_keys, f, indent=2)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    os.chmod(API_KEYS_FILE, 0o600)
```

---

## LOW SEVERITY ISSUES

### L1: Information Disclosure via Server Headers
**Location:** `phishing-guard-daemon/src/api_server.py`

**Issue:**
Default Python HTTP server headers reveal version information.

**Remediation:**
```python
def version_string(self):
    return "PhishingGuard/2.0.0"
```

---

### L2: Missing IPv6 Support in Localhost Check
**Location:** `phishing-guard-daemon/src/api_server.py` (line 180)

**Issue:**
```python
if client_ip not in ['127.0.0.1', 'localhost', '::1']:
```

May not handle all IPv6 localhost variants.

**Remediation:**
```python
import ipaddress

def is_localhost(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback
    except ValueError:
        return ip == 'localhost'
```

---

## ADDITIONAL SECURITY RECOMMENDATIONS

### 1. Implement Content Security Policy
Add CSP headers to prevent XSS attacks:
```python
Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'
```

### 2. Add Request Signing
For extension-to-API communication, implement request signing:
```python
import hmac
import hashlib

def sign_request(payload: dict, secret: str) -> str:
    message = json.dumps(payload, sort_keys=True)
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
```

### 3. Implement API Versioning
Add version prefix to all endpoints:
```
/api/v1/analyze
/api/v2/analyze
```

### 4. Add Health Check Authentication
Health endpoints should require authentication if they expose sensitive info:
```python
@app.get("/health")
async def health_check(auth: bool = Depends(optional_auth)):
    if auth:
        return detailed_health_info
    return basic_health_info
```

### 5. Use Secure Headers Middleware
Implement comprehensive security headers:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

app.add_middleware(HTTPSRedirectMiddleware)  # Force HTTPS
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.example.com"])
```

### 6. Implement Audit Logging
Add structured audit logging:
```python
import structlog

logger = structlog.get_logger()

logger.info(
    "url_analyzed",
    user_id=user.get("sub"),
    url=sanitize_url(request.url),
    classification=result["classification"],
    ip_address=request.client.host,
    timestamp=datetime.utcnow().isoformat()
)
```

---

## PRIORITY REMEDIATION CHECKLIST

### Immediate (Critical - Fix within 24 hours)
- [ ] C1: Implement proper authentication validation
- [ ] C2: Remove hardcoded credentials from extensions
- [ ] C3: Add HTTPS support to daemon

### High Priority (Fix within 1 week)
- [ ] H1: Fix CORS configuration
- [ ] H2: Secure token storage
- [ ] H3: Add request size limits
- [ ] H4: Increase RSA key size
- [ ] H6: Remove localhost bypass

### Medium Priority (Fix within 1 month)
- [ ] M1: Sanitize logged URLs
- [ ] M3: Configure Redis for production
- [ ] M7: Add version constraints
- [ ] M8: Add file locking

### Ongoing
- [ ] Regular dependency audits with `pip-audit` or `safety`
- [ ] Implement security scanning in CI/CD
- [ ] Conduct penetration testing
- [ ] Review access logs regularly

---

## COMPLIANCE NOTES

### OWASP Top 10 Mapping
- **A01: Broken Access Control** - C1, H6
- **A02: Cryptographic Failures** - C3, H4, H5
- **A03: Injection** - H9 (mitigated)
- **A05: Security Misconfiguration** - H1, H7, C2
- **A07: Identification and Authentication Failures** - C1, H6
- **A09: Security Logging and Monitoring Failures** - M1, H10

---

## CONCLUSION

The phishing detection projects have functional security controls for URL validation and SSRF protection, but critical vulnerabilities exist in authentication mechanisms and secure communications. Immediate attention is required for the Critical and High severity issues identified in this audit.

**Risk Rating: HIGH** - Not recommended for production deployment without remediation of Critical issues.

---

*End of Security Audit Report*
