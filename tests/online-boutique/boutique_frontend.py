"""Google Online Boutique - Frontend & Cart Microservice.

Instrumented with Aegis IAST Runtime Agent to monitor frontend checkout redirects
(Open Redirect - CWE-601) and cart session state restoration (Unsafe Deserialization - CWE-502).
Includes an interactive e-commerce storefront and live Aegis IAST Vulnerability Playground.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import urllib.request
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

# Add Aegis Python Agent to sys.path
AGENT_SRC = Path(__file__).resolve().parents[2] / "agents" / "runtime" / "python-agent" / "src"
if str(AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(AGENT_SRC))

# Add current dir to sys.path for seeder import
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from aegis_python_agent import (
    AegisAgent,
    AegisSecurityBlockException,
    check_deserialization_sink,
    check_open_redirect_sink,
    mark_tainted,
)

logger = logging.getLogger("boutique_frontend")

# Initialize Aegis Agent for Frontend Service
agent = AegisAgent.start(
    agent_id="online-boutique-frontend-svc-agent",
    organization_id="00000000-0000-0000-0000-000000000001",
)

app = FastAPI(title="Google Online Boutique - Frontend Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(AegisSecurityBlockException)
async def aegis_block_handler(request: Request, exc: AegisSecurityBlockException):
    """Handle ADR active defense blocks, returning HTTP 403 problem details."""
    return JSONResponse(
        status_code=403,
        headers={"X-Aegis-Action": "BLOCKED"},
        content={
            "type": "https://aegis.security/errors/runtime-block",
            "title": "Aegis ADR Security Block",
            "status": 403,
            "detail": exc.message,
            "rule_key": exc.rule_key,
            "sink": exc.sink_signature,
            "action": "BLOCKED",
            "service": "boutique_frontend",
            "iast_finding_detected": True,
        },
    )


@app.get("/api/protection-mode")
async def get_protection_mode():
    """Retrieve current fleet-wide ADR protection mode."""
    return {
        "mode": agent.protection_mode,
        "available_modes": ["MONITOR", "BLOCK"],
        "fleet_services": ["recommendationservice", "emailservice", "adservice", "currencyservice", "boutique_frontend"],
    }


@app.post("/api/protection-mode")
async def set_protection_mode(payload: dict[str, Any]):
    """Synchronize ADR protection mode across all 5 Google Online Boutique microservices."""
    new_mode = payload.get("mode", "MONITOR").upper()
    if new_mode not in ("MONITOR", "BLOCK"):
        return JSONResponse(status_code=400, content={"error": f"Invalid mode '{new_mode}'. Use 'MONITOR' or 'BLOCK'."})

    agent.set_protection_mode(new_mode)
    logger.info("Boutique Frontend ADR protection mode set to %s", new_mode)

    # Propagate to backend services
    fleet_ports = [8091, 8092, 8093, 8094]
    sync_results = {}
    for p in fleet_ports:
        url = f"http://127.0.0.1:{p}/api/protection-mode"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps({"mode": new_mode}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                sync_results[p] = resp.status == 200
        except Exception as exc:
            sync_results[p] = f"offline/error: {exc}"

    return {
        "status": "success",
        "mode": agent.protection_mode,
        "fleet_sync": sync_results,
    }



@app.middleware("http")
async def aegis_iast_middleware(request: Request, call_next):
    """Aegis IAST Middleware: Initializes request context and taints query parameters."""
    route_path = request.url.path
    method = request.method
    params = dict(request.query_params)

    trace_id = agent.wrap_request(route_path, method, params)
    try:
        response = await call_next(request)
        response.headers["X-Aegis-Trace-ID"] = trace_id
        return response
    finally:
        agent.finish_request()


VULNERABILITY_CATALOG = [
    {
        "id": "sql-injection",
        "service": "recommendationservice",
        "name": "SQL Injection",
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "port": 8091,
        "endpoint": "/api/recommendations/raw_search?category=vintage%27%20OR%20%271%27%3D%271",
        "method": "GET",
        "payload": "category=vintage' OR '1'='1",
        "sink": "recommendation_svc.sqlite3.execute",
        "description": "Unescaped single quotes bypass category filter and dump entire catalog.",
    },
    {
        "id": "path-traversal",
        "service": "recommendationservice",
        "name": "Path Traversal",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "port": 8091,
        "endpoint": "/api/recommendations/catalog?asset_name=../../../../etc/passwd",
        "method": "GET",
        "payload": "asset_name=../../../../etc/passwd",
        "sink": "recommendation_svc.open_asset",
        "description": "Dot-dot-slash sequence breaks out of assets folder to read sensitive system files.",
    },
    {
        "id": "log-injection",
        "service": "emailservice",
        "name": "Log Injection / CRLF",
        "cwe": "CWE-117",
        "severity": "MEDIUM",
        "port": 8092,
        "endpoint": "/api/email/send",
        "method": "POST",
        "payload": json.dumps({"email": "attacker@evil.com", "order_id": "ORD-9999", "note": "Delivered\nADMIN STATUS: ACCESS GRANTED"}),
        "content_type": "application/json",
        "sink": "email_svc.logging.info",
        "description": "Newline injection injects forged administrative audit log events.",
    },
    {
        "id": "xxe",
        "service": "emailservice",
        "name": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "severity": "CRITICAL",
        "port": 8092,
        "endpoint": "/api/email/template",
        "method": "POST",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "content_type": "application/xml",
        "sink": "email_svc.xml.etree.ElementTree.fromstring",
        "description": "External entity reference in XML email template allows local file disclosure.",
    },
    {
        "id": "reflected-xss",
        "service": "adservice",
        "name": "Reflected XSS",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "port": 8093,
        "endpoint": "/api/ads?context_keys=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
        "method": "GET",
        "payload": "context_keys=<script>alert('XSS')</script>",
        "sink": "ad_svc.HTMLResponse",
        "description": "Ad context parameter rendered directly into HTML response banner without escaping.",
    },
    {
        "id": "command-injection",
        "service": "adservice",
        "name": "OS Command Injection",
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "port": 8093,
        "endpoint": "/api/ads/telemetry?host=127.0.0.1%3B%20whoami",
        "method": "GET",
        "payload": "host=127.0.0.1; whoami",
        "sink": "ad_svc.subprocess.Popen",
        "description": "Semicolon shell separator executes arbitrary system commands via telemetry diagnostic ping.",
    },
    {
        "id": "ssrf",
        "service": "currencyservice",
        "name": "Server-Side Request Forgery",
        "cwe": "CWE-918",
        "severity": "HIGH",
        "port": 8094,
        "endpoint": "/api/currency/rates?provider_url=http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "payload": "provider_url=http://169.254.169.254/latest/meta-data/",
        "sink": "currency_svc.urllib.urlopen",
        "description": "Unrestricted provider URL triggers HTTP requests to internal cloud metadata service.",
    },
    {
        "id": "header-injection",
        "service": "currencyservice",
        "name": "HTTP Header Injection",
        "cwe": "CWE-113",
        "severity": "MEDIUM",
        "port": 8094,
        "endpoint": "/api/currency/convert?from_curr=USD&to_curr=EUR&amount=10.0&custom_header=val%0d%0aSet-Cookie:%20session=stolen",
        "method": "GET",
        "payload": "custom_header=val\\r\\nSet-Cookie: session=stolen",
        "sink": "currency_svc.Response.headers",
        "description": "CRLF characters in header values inject malicious Set-Cookie response headers.",
    },
    {
        "id": "open-redirect",
        "service": "boutique_frontend",
        "name": "Open Redirect",
        "cwe": "CWE-601",
        "severity": "MEDIUM",
        "port": 8095,
        "endpoint": "/api/cart/checkout?return_url=http://attacker-controlled-phishing.com",
        "method": "GET",
        "payload": "return_url=http://attacker-controlled-phishing.com",
        "sink": "boutique_frontend.RedirectResponse",
        "description": "Unvalidated return_url parameter allows redirecting checkout users to phishing sites.",
    },
    {
        "id": "unsafe-deserialization",
        "service": "boutique_frontend",
        "name": "Unsafe Deserialization",
        "cwe": "CWE-502",
        "severity": "CRITICAL",
        "port": 8095,
        "endpoint": "/api/cart/restore",
        "method": "POST",
        "payload": "cos\\nsystem\\n(S'whoami'\\ntR.",
        "content_type": "application/octet-stream",
        "sink": "boutique_frontend.pickle.loads",
        "description": "Python pickle opcode stream executes arbitrary shell code during cart restoration.",
    },
]


@app.get("/api/vulnerabilities")
async def list_vulnerabilities():
    """List all instrumented OWASP vulnerability vectors across Online Boutique."""
    return {"items": VULNERABILITY_CATALOG}


@app.post("/api/simulate/{vuln_id}")
async def simulate_vulnerability(vuln_id: str):
    """Execute a specific vulnerability attack vector and return the IAST detection result."""
    import urllib.error
    target = next((v for v in VULNERABILITY_CATALOG if v["id"] == vuln_id), None)
    if not target:
        return JSONResponse(status_code=404, content={"error": f"Vulnerability {vuln_id} not found"})

    # For local service endpoints (port 8095), handle in-process to avoid async event loop self-deadlock
    if target["port"] == 8095:
        trace_id = f"py-trace-{uuid.uuid4().hex[:12]}"
        try:
            if vuln_id == "open-redirect":
                res_json = await process_checkout(return_url="http://attacker-controlled-phishing.com")
            elif vuln_id == "unsafe-deserialization":
                tainted_payload = mark_tainted("cos\nsystem\n(S'whoami'\ntR.", source_kind="BODY", source_name="cart_payload")
                finding = check_deserialization_sink(tainted_payload, sink_signature="boutique_frontend.pickle.loads")
                if finding:
                    agent.event_buffer.append(finding)
                    if agent.protection_mode == "BLOCK":
                        raise AegisSecurityBlockException(
                            "Blocked Unsafe Deserialization opcode execution.",
                            rule_key="unsafe-deserialization",
                            sink_signature="boutique_frontend.pickle.loads",
                        )
                res_json = {
                    "service": "boutique_frontend",
                    "action": "restore_cart",
                    "cart_status": "restored",
                    "iast_finding_detected": finding is not None,
                    "finding": finding,
                }
            else:
                res_json = {}
            return {
                "status": "success",
                "http_status": 200,
                "vulnerability": target,
                "trace_id": trace_id,
                "response": res_json,
                "iast_detected": res_json.get("iast_finding_detected", False),
                "blocked": False,
            }
        except AegisSecurityBlockException as exc:
            return {
                "status": "blocked",
                "http_status": 403,
                "vulnerability": target,
                "trace_id": trace_id,
                "response": {
                    "title": "Aegis ADR Security Block",
                    "detail": exc.message,
                    "sink": exc.sink_signature,
                    "rule_key": exc.rule_key,
                    "action": "BLOCKED",
                    "iast_finding_detected": True,
                },
                "iast_detected": True,
                "blocked": True,
            }

    url = f"http://127.0.0.1:{target['port']}{target['endpoint']}"
    method = target["method"]
    content_type = target.get("content_type", "application/json")
    data = None

    if method == "POST":
        raw_payload = target["payload"]
        if content_type == "application/octet-stream":
            data = b"cos\nsystem\n(S'whoami'\ntR."
        else:
            data = raw_payload.encode("utf-8")

    headers = {}
    if data is not None:
        headers["Content-Type"] = content_type

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            res_json = json.loads(body) if body.strip().startswith(("{", "[")) else {"raw_response": body}
            trace_id = resp.headers.get("X-Aegis-Trace-ID", "N/A")
            return {
                "status": "success",
                "http_status": resp.status,
                "vulnerability": target,
                "trace_id": trace_id,
                "response": res_json,
                "iast_detected": res_json.get("iast_finding_detected", False),
                "blocked": False,
            }
    except urllib.error.HTTPError as http_err:
        body = http_err.read().decode("utf-8", errors="replace")
        res_json = json.loads(body) if body.strip().startswith(("{", "[")) else {"raw_response": body}
        trace_id = http_err.headers.get("X-Aegis-Trace-ID", "N/A")
        is_block = http_err.code == 403
        return {
            "status": "blocked" if is_block else "error",
            "http_status": http_err.code,
            "vulnerability": target,
            "trace_id": trace_id,
            "response": res_json,
            "iast_detected": res_json.get("iast_finding_detected", False) or is_block,
            "blocked": is_block,
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": str(exc),
            "vulnerability": target,
            "iast_detected": False,
            "blocked": False,
        }


@app.post("/api/simulate-all")
async def simulate_all():
    """Run all 10 vulnerability vectors sequentially and trigger Control Plane findings sync."""
    results = []
    for vuln in VULNERABILITY_CATALOG:
        res = await simulate_vulnerability(vuln["id"])
        results.append(res)

    # Sync to Control Plane database
    sync_status = "synced"
    try:
        from seed_online_boutique_findings import main as seed_main
        await seed_main()
    except Exception as exc:
        sync_status = f"sync error: {exc}"

    return {
        "executed_count": len(results),
        "detected_count": sum(1 for r in results if r.get("iast_detected")),
        "blocked_count": sum(1 for r in results if r.get("blocked")),
        "control_plane_sync": sync_status,
        "results": results,
    }


@app.get("/api/cart/checkout")
async def process_checkout(return_url: str = "/cart", remediated: bool = False):
    """Process shopping cart checkout and redirect customer to post-checkout page.
    
    Security Sink: Open Redirect (CWE-601)
    """
    if remediated:
        # Remediation: Enforce relative URL paths and deny external protocols
        if not return_url.startswith("/") or return_url.startswith("//"):
            return_url = "/cart"
        return {
            "service": "boutique_frontend",
            "action": "checkout",
            "redirect_target": return_url,
            "remediated": True,
            "iast_finding_detected": False,
            "finding": None,
            "message": "Domain validated: Open redirect prevented.",
        }

    tainted_url = mark_tainted(return_url, source_kind="PARAMETER", source_name="return_url")

    finding = check_open_redirect_sink(tainted_url, sink_signature="boutique_frontend.RedirectResponse")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked Open Redirect to external unvalidated destination domain.",
                rule_key="open-redirect",
                sink_signature="boutique_frontend.RedirectResponse",
            )

    return {
        "service": "boutique_frontend",
        "action": "checkout",
        "redirect_target": return_url,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.post("/api/cart/restore")
async def restore_saved_cart(request: Request, remediated: bool = False):
    """Restore serialized shopping cart session.
    
    Security Sink: Unsafe Deserialization (CWE-502)
    """
    body_bytes = await request.body()
    if remediated:
        try:
            cart_json = json.loads(body_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            cart_json = {"items": [], "status": "safe_empty_cart"}
        return {
            "service": "boutique_frontend",
            "action": "restore_cart",
            "cart_status": "restored_safe_json",
            "remediated": True,
            "iast_finding_detected": False,
            "finding": None,
            "message": "Deserialized using safe JSON parser. RCE payload negated.",
        }

    body_str = body_bytes.decode("utf-8", errors="ignore")
    tainted_payload = mark_tainted(body_str, source_kind="BODY", source_name="cart_payload")

    finding = check_deserialization_sink(tainted_payload, sink_signature="boutique_frontend.pickle.loads")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked Unsafe Deserialization opcode execution.",
                rule_key="unsafe-deserialization",
                sink_signature="boutique_frontend.pickle.loads",
            )

    return {
        "service": "boutique_frontend",
        "action": "restore_cart",
        "cart_status": "restored",
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.get("/", response_class=HTMLResponse)
async def serve_storefront():
    """Interactive storefront landing page with live Aegis IAST detection & attack testing console."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Google Online Boutique — Aegis IAST Vulnerable App</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-main: #0B0F19;
      --bg-card: #111827;
      --bg-card-hover: #1F2937;
      --border: #374151;
      --primary: #3B82F6;
      --primary-hover: #2563EB;
      --primary-glow: rgba(59, 130, 246, 0.25);
      --accent: #10B981;
      --warning: #F59E0B;
      --danger: #EF4444;
      --danger-glow: rgba(239, 68, 68, 0.25);
      --text-main: #F9FAFB;
      --text-muted: #9CA3AF;
      --text-dim: #6B7280;
      --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-main);
      color: var(--text-main);
      font-family: var(--font-sans);
      line-height: 1.5;
      min-height: 100vh;
    }
    header {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .brand-logo {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      background: linear-gradient(135deg, #3B82F6, #8B5CF6);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.25rem;
      color: #fff;
      box-shadow: 0 4px 12px var(--primary-glow);
    }
    .brand-title {
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .brand-subtitle {
      font-size: 0.75rem;
      color: var(--text-muted);
      font-weight: 500;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .iast-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34D399;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background: #10B981;
      border-radius: 50%;
      box-shadow: 0 0 8px #10B981;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
      100% { opacity: 1; transform: scale(1); }
    }
    .btn-console {
      background: linear-gradient(135deg, #2563EB, #1D4ED8);
      color: #fff;
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 600;
      padding: 0.5rem 1.1rem;
      border-radius: 8px;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      box-shadow: 0 4px 14px var(--primary-glow);
      transition: all 0.2s;
    }
    .btn-console:hover {
      background: linear-gradient(135deg, #1D4ED8, #1E40AF);
      transform: translateY(-1px);
    }
    main {
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem;
    }
    .hero {
      background: radial-gradient(circle at 50% -20%, rgba(59, 130, 246, 0.15), transparent 70%),
                  linear-gradient(180deg, var(--bg-card), var(--bg-main));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem;
      margin-bottom: 2rem;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .hero h1 {
      font-size: 2.25rem;
      font-weight: 800;
      letter-spacing: -0.03em;
      margin-bottom: 0.75rem;
      background: linear-gradient(180deg, #FFFFFF, #9CA3AF);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero p {
      color: var(--text-muted);
      font-size: 1.05rem;
      max-width: 760px;
      margin: 0 auto 1.5rem auto;
    }
    .fleet-pills {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 0.75rem;
      margin-top: 1.5rem;
    }
    .fleet-pill {
      background: rgba(31, 41, 55, 0.8);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.4rem 0.85rem;
      font-size: 0.8rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-family: var(--font-mono);
    }
    .fleet-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10B981;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 1024px) {
      .grid-2 { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.75rem;
      display: flex;
      flex-direction: column;
    }
    .panel-title {
      font-size: 1.25rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .panel-desc {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-bottom: 1.25rem;
    }
    /* Products Grid */
    .products-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .product-card {
      background: #1F2937;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: border-color 0.2s;
    }
    .product-card:hover {
      border-color: var(--primary);
    }
    .product-name {
      font-weight: 600;
      font-size: 0.95rem;
      margin-bottom: 0.25rem;
    }
    .product-cat {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.75rem;
    }
    .product-price {
      font-size: 1.15rem;
      font-weight: 700;
      color: #34D399;
      margin-bottom: 0.75rem;
    }
    .btn-buy {
      background: var(--primary);
      border: none;
      color: white;
      font-weight: 600;
      font-size: 0.8rem;
      padding: 0.5rem;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .btn-buy:hover {
      background: var(--primary-hover);
    }
    /* Interactive Controls */
    .action-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-bottom: 1rem;
    }
    .btn-action {
      background: #1F2937;
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.5rem 1rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s;
    }
    .btn-action:hover {
      background: #374151;
      border-color: var(--primary);
    }
    .btn-simulate-all {
      background: linear-gradient(135deg, #EF4444, #DC2626);
      border: none;
      color: white;
      font-weight: 700;
      font-size: 0.9rem;
      padding: 0.75rem 1.5rem;
      border-radius: 10px;
      cursor: pointer;
      box-shadow: 0 4px 16px var(--danger-glow);
      display: flex;
      align-items: center;
      gap: 0.6rem;
      transition: all 0.2s;
    }
    .btn-simulate-all:hover {
      background: linear-gradient(135deg, #DC2626, #B91C1C);
      transform: translateY(-1px);
    }
    /* Vulnerability Cards */
    .vuln-list {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      max-height: 520px;
      overflow-y: auto;
      padding-right: 0.5rem;
    }
    .vuln-item {
      background: #1F2937;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.85rem 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      transition: border-color 0.2s;
    }
    .vuln-item:hover {
      border-color: #4B5563;
    }
    .vuln-meta {
      flex: 1;
    }
    .vuln-title {
      font-size: 0.9rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.25rem;
    }
    .badge-cwe {
      font-size: 0.7rem;
      font-family: var(--font-mono);
      background: #374151;
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      color: var(--text-muted);
    }
    .badge-sev-critical {
      background: rgba(239, 68, 68, 0.2);
      color: #F87171;
      border: 1px solid rgba(239, 68, 68, 0.4);
      font-size: 0.65rem;
      font-weight: 700;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
    }
    .badge-sev-high {
      background: rgba(245, 158, 11, 0.2);
      color: #FBBF24;
      border: 1px solid rgba(245, 158, 11, 0.4);
      font-size: 0.65rem;
      font-weight: 700;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
    }
    .badge-sev-medium {
      background: rgba(59, 130, 246, 0.2);
      color: #60A5FA;
      border: 1px solid rgba(59, 130, 246, 0.4);
      font-size: 0.65rem;
      font-weight: 700;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
    }
    .vuln-sink {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-dim);
    }
    .btn-test-vuln {
      background: #374151;
      border: 1px solid #4B5563;
      color: #fff;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.2s;
    }
    .btn-test-vuln:hover {
      background: var(--danger);
      border-color: var(--danger);
    }
    /* Live Inspector Terminal */
    .terminal-box {
      background: #06090E;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      min-height: 220px;
      max-height: 340px;
      overflow-y: auto;
      color: #E5E7EB;
    }
    .term-line {
      margin-bottom: 0.4rem;
      word-break: break-all;
    }
    .term-success { color: #34D399; }
    .term-iast { color: #F87171; font-weight: 700; }
    .term-shield { color: #FB7185; font-weight: 700; }
    .term-warn { color: #FBBF24; }
    .term-info { color: #60A5FA; }
    .term-dim { color: #6B7280; }
    .badge-blocking {
      background: rgba(239, 68, 68, 0.15) !important;
      border: 1px solid rgba(239, 68, 68, 0.4) !important;
      color: #F87171 !important;
    }
    .pulse-dot-red {
      width: 8px;
      height: 8px;
      background: #EF4444;
      border-radius: 50%;
      box-shadow: 0 0 8px #EF4444;
      animation: pulse 1.2s infinite;
    }
    .adr-deck {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 2rem;
      flex-wrap: wrap;
      background: rgba(17, 24, 39, 0.85);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.85rem 1.5rem;
      margin-top: 1.5rem;
    }
    .adr-group {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .adr-label {
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-muted);
    }
    .mode-toggle-wrap {
      display: flex;
      background: #0B0F19;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.2rem;
      gap: 0.2rem;
    }
    .mode-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s;
    }
    .mode-btn.active.monitor {
      background: rgba(16, 185, 129, 0.15);
      color: #34D399;
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.2);
    }
    .mode-btn.active.block {
      background: rgba(239, 68, 68, 0.2);
      color: #F87171;
      box-shadow: 0 0 10px rgba(239, 68, 68, 0.25);
    }
    .switch-wrap {
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }
    .switch {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
    }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute;
      cursor: pointer;
      top: 0; left: 0; right: 0; bottom: 0;
      background-color: #374151;
      transition: .3s;
      border-radius: 24px;
    }
    .slider:before {
      position: absolute;
      content: "";
      height: 18px;
      width: 18px;
      left: 3px;
      bottom: 3px;
      background-color: white;
      transition: .3s;
      border-radius: 50%;
    }
    input:checked + .slider {
      background-color: #10B981;
    }
    input:checked + .slider:before {
      transform: translateX(20px);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand-wrap">
      <div class="brand-logo">OB</div>
      <div>
        <div class="brand-title">Google Online Boutique</div>
        <div class="brand-subtitle">IAST Instrumented Vulnerability Testbed</div>
      </div>
    </div>
    <div class="header-actions">
      <div id="adrBadge" class="iast-badge">
        <span class="pulse-dot"></span>
        ADR: MONITOR (Passive)
      </div>
      <a href="http://localhost:3100" target="_blank" class="btn-console">
        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
        Open Security Console (:3100)
      </a>
    </div>
  </header>

  <main>
    <div class="hero">
      <h1>Google Online Boutique</h1>
      <p>Interactive microservices testbed instrumented with the <strong>Aegis IAST Runtime Agent</strong> and <strong>Active Defense & Response (ADR)</strong>. Real-time taint tracking detects security-sensitive sinks with zero false-positive crawlers.</p>
      
      <!-- Interactive ADR Policy and Remediation Deck -->
      <div class="adr-deck">
        <div class="adr-group">
          <span class="adr-label">Fleet ADR Protection Mode:</span>
          <div class="mode-toggle-wrap">
            <button id="btnModeMonitor" class="mode-btn active monitor" onclick="setFleetProtectionMode('MONITOR')">
              MONITOR (Passive Detect)
            </button>
            <button id="btnModeBlock" class="mode-btn block" onclick="setFleetProtectionMode('BLOCK')">
              BLOCK (Active ADR Intercept)
            </button>
          </div>
        </div>

        <div class="adr-group">
          <span class="adr-label">Remediation Sandbox:</span>
          <div class="switch-wrap">
            <label class="switch">
              <input type="checkbox" id="remediationToggle" onchange="handleRemediationToggle()">
              <span class="slider"></span>
            </label>
            <span id="remediationLabel" style="font-size:0.8rem; font-weight:600; color:var(--text-muted);">Vulnerable Baseline</span>
          </div>
        </div>
      </div>

      <div class="fleet-pills">
        <div class="fleet-pill"><span class="fleet-dot"></span> recommendation_svc :8091</div>
        <div class="fleet-pill"><span class="fleet-dot"></span> email_svc :8092</div>
        <div class="fleet-pill"><span class="fleet-dot"></span> ad_service :8093</div>
        <div class="fleet-pill"><span class="fleet-dot"></span> currency_svc :8094</div>
        <div class="fleet-pill"><span class="fleet-dot"></span> boutique_frontend :8095</div>
      </div>
    </div>

    <div class="grid-2">
      <!-- Left Panel: Online Boutique Storefront -->
      <div class="panel">
        <div class="panel-title">
          <span>Featured Boutique Catalog</span>
          <span style="font-size:0.8rem; font-weight:normal; color:var(--text-muted);">Port 8095 & 8091</span>
        </div>
        <div class="panel-desc">Browse products and trigger legitimate e-commerce transactions across the microservices.</div>
        
        <div class="products-grid">
          <div class="product-card">
            <div>
              <div class="product-name">Vintage Typewriter</div>
              <div class="product-cat">Vintage</div>
            </div>
            <div class="product-price">$67.99</div>
            <button class="btn-buy" onclick="checkoutProduct('Vintage Typewriter')">Buy Now</button>
          </div>
          <div class="product-card">
            <div>
              <div class="product-name">Vintage Camera Lens</div>
              <div class="product-cat">Photography</div>
            </div>
            <div class="product-price">$12.49</div>
            <button class="btn-buy" onclick="checkoutProduct('Vintage Camera Lens')">Buy Now</button>
          </div>
          <div class="product-card">
            <div>
              <div class="product-name">Barista Kit</div>
              <div class="product-cat">Cookware</div>
            </div>
            <div class="product-price">$49.99</div>
            <button class="btn-buy" onclick="checkoutProduct('Barista Kit')">Buy Now</button>
          </div>
          <div class="product-card">
            <div>
              <div class="product-name">Air Plant Terrarium</div>
              <div class="product-cat">Gardening</div>
            </div>
            <div class="product-price">$12.99</div>
            <button class="btn-buy" onclick="checkoutProduct('Air Plant Terrarium')">Buy Now</button>
          </div>
        </div>

        <div style="font-size:0.85rem; font-weight:600; margin-bottom:0.6rem; color:var(--text-muted);">Benign Microservice Operations:</div>
        <div class="action-row">
          <button class="btn-action" onclick="fetchRecommendations()">Fetch Recommendations (:8091)</button>
          <button class="btn-action" onclick="convertCurrency()">Currency Rates (:8094)</button>
          <button class="btn-action" onclick="sendReceipt()">Dispatch Email Receipt (:8092)</button>
          <button class="btn-action" onclick="fetchAd()">Fetch Deals (:8093)</button>
        </div>
      </div>

      <!-- Right Panel: Vulnerability Lab -->
      <div class="panel">
        <div class="panel-title">
          <span>Aegis IAST Vulnerability Lab</span>
          <button class="btn-simulate-all" onclick="simulateAllAttacks()">
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
            Trigger All 10 Attacks & Sync DB
          </button>
        </div>
        <div class="panel-desc">10 instrumented OWASP vulnerability vectors across all 5 microservices. Test individually or in bulk.</div>
        
        <div class="vuln-list" id="vulnList">
          <!-- Populated by JavaScript -->
        </div>
      </div>
    </div>

    <!-- Live Execution Telemetry -->
    <div class="panel">
      <div class="panel-title">
        <span>Live Aegis IAST Telemetry & Inspection Stream</span>
        <button class="btn-action" onclick="clearTerminal()" style="font-size:0.75rem; padding:0.25rem 0.6rem;">Clear</button>
      </div>
      <div class="terminal-box" id="term">
        <div class="term-line term-dim">==================================================================================</div>
        <div class="term-line term-info">[SYSTEM] Google Online Boutique Microservices connected to Aegis IAST Runtime.</div>
        <div class="term-line term-info">[SYSTEM] Mode: MONITOR (Passive detection). ADR Active Defense available.</div>
        <div class="term-line term-dim">==================================================================================</div>
      </div>
    </div>
  </main>

  <script>
    let VULNS = [];
    let currentProtectionMode = "MONITOR";
    let isRemediatedActive = false;

    async function initStorefront() {
      try {
        const pRes = await fetch('/api/protection-mode');
        const pData = await pRes.json();
        currentProtectionMode = pData.mode || "MONITOR";
        updateModeUI();

        const vRes = await fetch('/api/vulnerabilities');
        const vData = await vRes.json();
        VULNS = vData.items || [];
        renderVulns();
      } catch (err) {
        logTerm(`[ERROR] Initialization failed: ${err.message}`, "term-iast");
      }
    }

    function logTerm(text, cls = "") {
      const term = document.getElementById('term');
      const line = document.createElement('div');
      line.className = 'term-line ' + cls;
      line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
      term.appendChild(line);
      term.scrollTop = term.scrollHeight;
    }

    function clearTerminal() {
      document.getElementById('term').innerHTML = '';
    }

    async function setFleetProtectionMode(mode) {
      logTerm(`[ADR CONFIG] Switching fleet protection policy to: ${mode}...`, "term-info");
      try {
        const res = await fetch('/api/protection-mode', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode })
        });
        const data = await res.json();
        currentProtectionMode = data.mode;
        updateModeUI();
        if (currentProtectionMode === 'BLOCK') {
          logTerm(`[ADR ACTIVE] Protection Mode: BLOCK. Exploits targeting sensitive sinks will be intercepted with HTTP 403!`, "term-shield");
        } else {
          logTerm(`[ADR PASSIVE] Protection Mode: MONITOR. Vulnerabilities will be passively tracked without breaking user flow.`, "term-success");
        }
      } catch (err) {
        logTerm(`[ERROR] Failed to switch protection mode: ${err.message}`, "term-iast");
      }
    }

    function handleRemediationToggle() {
      isRemediatedActive = document.getElementById('remediationToggle').checked;
      const label = document.getElementById('remediationLabel');
      if (isRemediatedActive) {
        label.textContent = "Remediated (Secure Coding)";
        label.style.color = "#34D399";
        logTerm(`[REMEDIATION SANDBOX] Mode: REMEDIATED. Operations will apply parameterized queries and strict domain whitelists.`, "term-success");
      } else {
        label.textContent = "Vulnerable Baseline";
        label.style.color = "var(--text-muted)";
        logTerm(`[REMEDIATION SANDBOX] Mode: VULNERABLE BASELINE restored.`, "term-warn");
      }
    }

    function updateModeUI() {
      const btnMon = document.getElementById('btnModeMonitor');
      const btnBlk = document.getElementById('btnModeBlock');
      const badge = document.getElementById('adrBadge');

      if (currentProtectionMode === 'BLOCK') {
        btnMon.classList.remove('active');
        btnBlk.classList.add('active');
        badge.className = 'iast-badge badge-blocking';
        badge.innerHTML = '<span class="pulse-dot-red"></span> ADR: BLOCK (Active Defense)';
      } else {
        btnBlk.classList.remove('active');
        btnMon.classList.add('active');
        badge.className = 'iast-badge';
        badge.innerHTML = '<span class="pulse-dot"></span> ADR: MONITOR (Passive)';
      }
    }

    function renderVulns() {
      const container = document.getElementById('vulnList');
      container.innerHTML = '';
      VULNS.forEach((v) => {
        const item = document.createElement('div');
        item.className = 'vuln-item';
        const sevClass = v.severity === 'CRITICAL' ? 'badge-sev-critical' : (v.severity === 'HIGH' ? 'badge-sev-high' : 'badge-sev-medium');
        item.innerHTML = `
          <div class="vuln-meta">
            <div class="vuln-title">
              <span>${v.name}</span>
              <span class="badge-cwe">${v.cwe}</span>
              <span class="${sevClass}">${v.severity}</span>
            </div>
            <div class="vuln-sink">Sink: ${v.sink} &bull; :${v.port}</div>
          </div>
          <button class="btn-test-vuln" onclick="simulateAttack('${v.id}')">Exploit Sink</button>
        `;
        container.appendChild(item);
      });
    }

    async function simulateAttack(vulnId) {
      const v = VULNS.find(item => item.id === vulnId);
      logTerm(`--> [EXPLOIT] Triggering ${v.name} (${v.cwe}) on ${v.service} (:${v.port})...`, "term-info");
      try {
        const res = await fetch(`/api/simulate/${vulnId}`, { method: 'POST' });
        const data = await res.json();
        if (data.blocked) {
          logTerm(`[SHIELD ACTIVE] Exploit BLOCKED by Aegis ADR before reaching sink! (HTTP 403 Forbidden)`, "term-shield");
          logTerm(`      Detail: ${data.response?.detail || 'Execution aborted'}`, "term-shield");
          logTerm(`      Rule: ${data.vulnerability?.name || v.name} (${data.vulnerability?.cwe || v.cwe}) | Sink: ${v.sink}`, "term-shield");
          logTerm(`      Zero process memory corruption; application kept resilient!`, "term-success");
        } else if (data.iast_detected) {
          logTerm(`[!!!] AEGIS IAST ALERT: Taint hit detected in sink: ${v.sink}`, "term-iast");
          logTerm(`      Rule: ${data.vulnerability.id} | Severity: ${data.vulnerability.severity} | Trace: ${data.trace_id}`, "term-iast");
          logTerm(`      Sink argument intercepted cleanly without app crash!`, "term-success");
        } else {
          logTerm(`[INFO] Request served: HTTP ${data.http_status}`, "term-dim");
        }
      } catch (err) {
        logTerm(`[ERROR] Execution failed: ${err.message}`, "term-iast");
      }
    }

    async function simulateAllAttacks() {
      logTerm(">>> STARTING FULL SUITE ATTACK SIMULATION (10 CWEs)...", "term-info");
      try {
        const res = await fetch('/api/simulate-all', { method: 'POST' });
        const data = await res.json();
        const blockedText = data.blocked_count ? ` (${data.blocked_count} Active ADR Blocks)` : '';
        logTerm(`>>> COMPLETED: ${data.detected_count}/${data.executed_count} Vulnerability Sinks Flagged by Aegis IAST!${blockedText}`, "term-success");
        logTerm(`>>> Control Plane Database: ${data.control_plane_sync}. Findings live in console!`, "term-info");
        logTerm(`>>> Open Console: http://localhost:3100/findings`, "term-success");
      } catch (err) {
        logTerm(`[ERROR] Full simulation failed: ${err.message}`, "term-iast");
      }
    }

    async function checkoutProduct(name) {
      logTerm(`[CART] Processing checkout for item "${name}"...`, "term-info");
      try {
        const url = isRemediatedActive
          ? '/api/cart/checkout?return_url=/confirmation&remediated=true'
          : '/api/cart/checkout?return_url=/confirmation';
        const res = await fetch(url);
        const data = await res.json();
        if (data.remediated) {
          logTerm(`[CART] Remediated checkout: Domain validated against allowlist. Clean!`, "term-success");
        } else {
          logTerm(`[CART] Checkout completed cleanly. Trace: ${res.headers.get('X-Aegis-Trace-ID') || 'N/A'} (No False Positive)`, "term-success");
        }
      } catch (err) {
        logTerm(`[ERROR] Checkout failed: ${err.message}`, "term-iast");
      }
    }

    async function fetchRecommendations() {
      logTerm(`[REC_SVC] Requesting benign recommendations category=cookware on :8091...`, "term-info");
      try {
        const res = await fetch('http://127.0.0.1:8091/api/recommendations?category=cookware');
        const data = await res.json();
        logTerm(`[REC_SVC] Received ${data.recommendations?.length || 0} products via parameterized SQL query. Clean!`, "term-success");
      } catch (err) {
        logTerm(`[REC_SVC] Failed: ${err.message}`, "term-iast");
      }
    }

    async function convertCurrency() {
      logTerm(`[CURR_SVC] Converting 100 USD to EUR on :8094...`, "term-info");
      try {
        const res = await fetch('http://127.0.0.1:8094/api/currency/convert?from_curr=USD&to_curr=EUR&amount=100.0');
        const data = await res.json();
        logTerm(`[CURR_SVC] 100 USD = ${data.converted_amount} EUR. Status: 200 OK`, "term-success");
      } catch (err) {
        logTerm(`[CURR_SVC] Failed: ${err.message}`, "term-iast");
      }
    }

    async function sendReceipt() {
      logTerm(`[EMAIL_SVC] Dispatching legitimate order confirmation on :8092...`, "term-info");
      try {
        const res = await fetch('http://127.0.0.1:8092/api/email/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com', order_id: 'ORD-7721', note: 'Gift wrap requested' })
        });
        const data = await res.json();
        logTerm(`[EMAIL_SVC] Confirmation sent to ${data.recipient}. Status: ${data.status}`, "term-success");
      } catch (err) {
        logTerm(`[EMAIL_SVC] Failed: ${err.message}`, "term-iast");
      }
    }

    async function fetchAd() {
      logTerm(`[AD_SVC] Requesting targeted advertisement on :8093...`, "term-info");
      try {
        const res = await fetch('http://127.0.0.1:8093/api/ads?context_keys=vintage');
        const data = await res.json();
        logTerm(`[AD_SVC] Received ad banner. Status: 200 OK`, "term-success");
      } catch (err) {
        logTerm(`[AD_SVC] Failed: ${err.message}`, "term-iast");
      }
    }

    initStorefront();
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8095)
