# Google Online Boutique IAST Test Suite

This directory contains a full microservices test environment based on **Google's Online Boutique** (`microservices-demo`) instrumented with **Aegis IAST Runtime Agents**.

## Online Boutique Microservices Architecture

```
                       ┌────────────────────────────────┐
                       │   Boutique Load & Test Harness │
                       │    (test_boutique_harness.py)  │
                       └───────────────┬────────────────┘
                                       │
                                       ▼
                       ┌────────────────────────────────┐
                       │   Online Boutique Frontend     │
                       │     (boutique_frontend.py)     │
                       └───────┬───────┬────────┬───────┘
                               │       │        │
           ┌───────────────────┘       │        └───────────────────┐
           ▼                           ▼                            ▼
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ Recommendation Svc   │    │      Ad Service      │    │   Currency Service   │
│(recommendation_svc.py)    │    │    (ad_service.py)   │    │(currency_service.py) │
└──────────┬───────────┘    └──────────────────────┘    └──────────────────────┘
           │
           ▼
┌──────────────────────┐
│    Email Service     │
│  (email_service.py)  │
└──────────────────────┘
```

## Instrumented Aegis Security Sinks

Each microservice is instrumented with Aegis IAST runtime instrumentation to detect security vulnerabilities during application execution:

| Microservice | Endpoint | Security Category | Sink Signature | CWE |
|--------------|----------|-------------------|----------------|-----|
| **Recommendation Service** | `GET /api/recommendations` | SQL Injection | `sqlite3.Cursor.execute` | CWE-89 |
| **Recommendation Service** | `GET /api/recommendations/catalog` | Path Traversal | `builtins.open` | CWE-22 |
| **Email Service** | `POST /api/email/send` | Log Injection | `logging.Logger.info` | CWE-117 |
| **Email Service** | `POST /api/email/template` | XML External Entity (XXE) | `xml.etree.ElementTree.fromstring` | CWE-611 |
| **Ad Service** | `GET /api/ads` | Reflected XSS | `fastapi.responses.HTMLResponse` | CWE-79 |
| **Ad Service** | `GET /api/ads/telemetry` | OS Command Injection | `subprocess.Popen` | CWE-78 |
| **Currency Service** | `GET /api/currency/rates` | SSRF | `urllib.request.urlopen` | CWE-918 |
| **Currency Service** | `GET /api/currency/convert` | Header Injection | `fastapi.responses.Response.headers` | CWE-113 |
| **Boutique Frontend** | `GET /api/cart/checkout` | Open Redirect | `fastapi.responses.RedirectResponse` | CWE-601 |
| **Boutique Frontend** | `POST /api/cart/restore` | Unsafe Deserialization | `pickle.loads` | CWE-502 |

## How to Start the App and Run on the Vulnerable App

### Option 1: Unified Launcher (Starts All Services & Runs Tests/Traffic)
To start the entire Aegis IAST platform (Control Plane API, Dashboard, Online Boutique microservices) and run security tests and traffic against the vulnerable app in one command:

```bash
# Python:
python start_boutique_demo.py

# Or via npm:
npm run demo:boutique

# Or in PowerShell:
.\start_boutique_demo.ps1
```

Options:
- `--test-only`: Run the 4-phase vulnerability test suite and exit cleanly.
- `--interval 0.5`: Adjust simulated traffic interval (default: 1.0s).
- `--attack-ratio 0.2`: Adjust proportion of attack payloads (default: 0.15).
- `--count 20`: Run a specific number of simulated transactions.
- `--mode BLOCK`: Start cluster in Active Defense & Response (ADR) blocking mode.

### Option 2: Execute Test Harness Directly
If services are already running, execute the automated 4-phase test suite directly:

```bash
python tests/online-boutique/test_boutique_harness.py
```
