# Aegis IAST OWASP Top 10 Vulnerable Test Application

A lightweight FastAPI application instrumented with the **Aegis Python IAST Agent** to verify real-time taint tracking and vulnerability detection across 10 OWASP categories.

## OWASP Top 10 Endpoints & Test Payloads

| # | Vulnerability Category | Endpoint | CWE | Sink Signature | Test Payload |
|---|------------------------|----------|-----|----------------|--------------|
| 1 | **SQL Injection** | `GET /api/users/search?name=...` | CWE-89 | `sqlite3.Cursor.execute` | `admin' OR '1'='1` |
| 2 | **OS Command Injection** | `GET /api/system/ping?host=...` | CWE-78 | `subprocess.Popen` | `127.0.0.1; whoami` |
| 3 | **Unsafe Deserialization** | `POST /api/data/deserialize` | CWE-502 | `pickle.loads` | Raw pickle byte stream |
| 4 | **XML External Entity (XXE)** | `POST /api/xml/parse` | CWE-611 | `xml.etree.ElementTree.fromstring` | `<!ENTITY xxe SYSTEM ...>` |
| 5 | **Path Traversal** | `GET /api/files/read?filename=...` | CWE-22 | `builtins.open` | `../../../../etc/passwd` |
| 6 | **Reflected XSS** | `GET /api/render/html?user_input=...` | CWE-79 | `fastapi.responses.HTMLResponse` | `<script>alert(1)</script>` |
| 7 | **Server-Side Request Forgery (SSRF)** | `GET /api/fetch/url?target=...` | CWE-918 | `urllib.request.urlopen` | `http://169.254.169.254/...` |
| 8 | **Open Redirect** | `GET /api/navigate/redirect?url=...` | CWE-601 | `fastapi.responses.RedirectResponse` | `http://example.com` |
| 9 | **HTTP Header Injection** | `GET /api/headers/set?custom_header=...` | CWE-113 | `fastapi.responses.Response.headers` | `val\r\nSet-Cookie: session=stolen` |
| 10 | **Log Injection** | `GET /api/system/log?msg=...` | CWE-117 | `logging.Logger.info` | `User logged in\nADMIN GRANTED` |

## How to Run & Verify

1. **Start Vulnerable Test App**:
   ```bash
   .\apps\api\.venv\Scripts\python.exe tests/vulnerable-app/app.py
   ```

2. **Run Full OWASP Top 10 Test Suite**:
   ```bash
   .\apps\api\.venv\Scripts\python.exe tests/vulnerable-app/test_harness.py
   ```
