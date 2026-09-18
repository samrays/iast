"""Google Online Boutique - Email Microservice.

Instrumented with Aegis IAST Python Agent to monitor order confirmation email dispatches
(Log Injection - CWE-117) and XML email template rendering (XXE Injection - CWE-611).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# Add Aegis Python Agent to sys.path
AGENT_SRC = Path(__file__).resolve().parents[2] / "agents" / "runtime" / "python-agent" / "src"
if str(AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(AGENT_SRC))

from aegis_python_agent import (
    AegisAgent,
    AegisSecurityBlockException,
    check_log_injection_sink,
    check_xxe_sink,
    mark_tainted,
)

logger = logging.getLogger("email_service")

# Initialize Aegis Agent for Email Service
agent = AegisAgent.start(
    agent_id="online-boutique-email-svc-agent",
    organization_id="00000000-0000-0000-0000-000000000001",
)

app = FastAPI(title="Google Online Boutique - Email Service")

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
    from fastapi.responses import JSONResponse
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
            "service": "emailservice",
            "iast_finding_detected": True,
        },
    )


@app.get("/api/protection-mode")
async def get_protection_mode():
    return {"service": "emailservice", "mode": agent.protection_mode}


@app.post("/api/protection-mode")
async def set_protection_mode(payload: dict):
    mode = payload.get("mode", "MONITOR").upper()
    agent.set_protection_mode(mode)
    return {"service": "emailservice", "mode": agent.protection_mode}



@app.middleware("http")
async def aegis_iast_middleware(request: Request, call_next):
    """Aegis IAST Middleware: Initializes request context and taints query/body data."""
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


@app.post("/api/email/send")
async def send_order_confirmation(request: Request):
    """Send order confirmation email to customer.
    
    Security Sink: Log Injection (CWE-117)
    """
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    recipient = body.get("email", "customer@example.com")
    order_id = body.get("order_id", "ORD-1001")
    note = body.get("note", "Thank you for shopping at Online Boutique!")

    tainted_note = mark_tainted(note, source_kind="BODY", source_name="note")
    log_msg = f"Order {order_id} confirmation dispatched to {recipient}. Customer Note: {tainted_note}"

    finding = check_log_injection_sink(log_msg, sink_signature="email_svc.logging.info")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked Log Injection attempt with newline/CRLF characters.",
                rule_key="log-injection",
                sink_signature="email_svc.logging.info",
            )

    logger.info(log_msg)

    return {
        "service": "emailservice",
        "status": "SENT",
        "recipient": recipient,
        "order_id": order_id,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.post("/api/email/template")
async def parse_email_template(request: Request):
    """Parse custom XML email template.
    
    Security Sink: XML External Entity (XXE) Injection (CWE-611)
    """
    body_bytes = await request.body()
    xml_str = body_bytes.decode("utf-8", errors="ignore")
    tainted_xml = mark_tainted(xml_str, source_kind="BODY", source_name="xml_template")

    finding = check_xxe_sink(tainted_xml, sink_signature="email_svc.xml.etree.ElementTree.fromstring")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked XML External Entity (XXE) attack payload.",
                rule_key="xxe",
                sink_signature="email_svc.xml.etree.ElementTree.fromstring",
            )

    return {
        "service": "emailservice",
        "template_status": "parsed",
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8092)
