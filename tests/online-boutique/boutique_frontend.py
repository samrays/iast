"""Google Online Boutique - Frontend & Cart Microservice.

Instrumented with Aegis IAST Runtime Agent to monitor frontend checkout redirects
(Open Redirect - CWE-601) and cart session state restoration (Unsafe Deserialization - CWE-502).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Add Aegis Python Agent to sys.path
AGENT_SRC = Path(__file__).resolve().parents[2] / "agents" / "runtime" / "python-agent" / "src"
if str(AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(AGENT_SRC))

from aegis_python_agent import (
    AegisAgent,
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


@app.get("/api/cart/checkout")
async def process_checkout(return_url: str = "/cart"):
    """Process shopping cart checkout and redirect customer to post-checkout page.
    
    Security Sink: Open Redirect (CWE-601)
    """
    tainted_url = mark_tainted(return_url, source_kind="PARAMETER", source_name="return_url")

    finding = check_open_redirect_sink(tainted_url, sink_signature="boutique_frontend.RedirectResponse")
    if finding:
        agent.event_buffer.append(finding)

    return {
        "service": "boutique_frontend",
        "action": "checkout",
        "redirect_target": return_url,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.post("/api/cart/restore")
async def restore_saved_cart(request: Request):
    """Restore serialized shopping cart session.
    
    Security Sink: Unsafe Deserialization (CWE-502)
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="ignore")
    tainted_payload = mark_tainted(body_str, source_kind="BODY", source_name="cart_payload")

    finding = check_deserialization_sink(tainted_payload, sink_signature="boutique_frontend.pickle.loads")
    if finding:
        agent.event_buffer.append(finding)

    return {
        "service": "boutique_frontend",
        "action": "restore_cart",
        "cart_status": "restored",
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8095)
