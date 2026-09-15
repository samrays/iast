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

## How to Execute the Online Boutique Test Suite

Run the test suite using Python:
```bash
python tests/online-boutique/test_boutique_harness.py
```
