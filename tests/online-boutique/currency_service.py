"""Google Online Boutique - Currency Microservice.

Instrumented with Aegis IAST Runtime Agent to monitor exchange rate lookups
(Server-Side Request Forgery SSRF - CWE-918) and custom response header settings
(HTTP Header Injection - CWE-113).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Add Aegis Python Agent to sys.path
AGENT_SRC = Path(__file__).resolve().parents[2] / "agents" / "runtime" / "python-agent" / "src"
if str(AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(AGENT_SRC))

from aegis_python_agent import (
    AegisAgent,
    AegisSecurityBlockException,
    check_header_injection_sink,
    check_ssrf_sink,
    mark_tainted,
)

logger = logging.getLogger("currency_service")

# Initialize Aegis Agent for Currency Service
agent = AegisAgent.start(
    agent_id="online-boutique-currency-svc-agent",
    organization_id="00000000-0000-0000-0000-000000000001",
)

app = FastAPI(title="Google Online Boutique - Currency Service")

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
            "service": "currencyservice",
            "iast_finding_detected": True,
        },
    )


@app.get("/api/protection-mode")
async def get_protection_mode():
    return {"service": "currencyservice", "mode": agent.protection_mode}


@app.post("/api/protection-mode")
async def set_protection_mode(payload: dict):
    mode = payload.get("mode", "MONITOR").upper()
    agent.set_protection_mode(mode)
    return {"service": "currencyservice", "mode": agent.protection_mode}



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


@app.get("/api/currency/rates")
async def fetch_exchange_rates(provider_url: str = "http://api.exchangerate.internal/latest"):
    """Fetch live currency exchange rates from specified upstream provider.
    
    Security Sink: Server-Side Request Forgery SSRF (CWE-918)
    """
    tainted_url = mark_tainted(provider_url, source_kind="PARAMETER", source_name="provider_url")

    finding = check_ssrf_sink(tainted_url, sink_signature="currency_svc.urllib.urlopen")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked Server-Side Request Forgery (SSRF) attempt targeting internal networks.",
                rule_key="ssrf",
                sink_signature="currency_svc.urllib.urlopen",
            )

    return {
        "service": "currencyservice",
        "provider_url": provider_url,
        "base_currency": "USD",
        "rates": {"EUR": 0.92, "GBP": 0.78, "JPY": 155.4, "CAD": 1.36},
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.get("/api/currency/convert")
async def convert_currency(from_curr: str = "USD", to_curr: str = "EUR", amount: float = 100.0, custom_header: str = ""):
    """Convert amount between currencies and inject custom tracking headers.
    
    Security Sink: HTTP Header Injection (CWE-113)
    """
    tainted_header = mark_tainted(custom_header, source_kind="PARAMETER", source_name="custom_header")

    finding = check_header_injection_sink(tainted_header, sink_signature="currency_svc.Response.headers")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked HTTP Header Injection CRLF payload.",
                rule_key="header-injection",
                sink_signature="currency_svc.Response.headers",
            )

    converted_amount = amount * 0.92 if to_curr == "EUR" else amount
    return {
        "service": "currencyservice",
        "from": from_curr,
        "to": to_curr,
        "original_amount": amount,
        "converted_amount": converted_amount,
        "custom_header_value": custom_header,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8094)
