"""Google Online Boutique - Ad Microservice.

Instrumented with Aegis IAST Runtime Agent to monitor targeted ad serving
(Reflected XSS - CWE-79) and ad telemetry diagnostic pings (OS Command Injection - CWE-78).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

# Add Aegis Python Agent to sys.path
AGENT_SRC = Path(__file__).resolve().parents[2] / "agents" / "runtime" / "python-agent" / "src"
if str(AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(AGENT_SRC))

from aegis_python_agent import (
    AegisAgent,
    check_command_sink,
    check_xss_sink,
    mark_tainted,
)

logger = logging.getLogger("ad_service")

# Initialize Aegis Agent for Ad Service
agent = AegisAgent.start(
    agent_id="online-boutique-ad-svc-agent",
    organization_id="00000000-0000-0000-0000-000000000001",
)

app = FastAPI(title="Google Online Boutique - Ad Service")


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


@app.get("/api/ads")
async def get_ads(context_keys: str = "photography"):
    """Fetch targeted advertisements based on category context keys.
    
    Security Sink: Reflected Cross-Site Scripting XSS (CWE-79)
    """
    tainted_context = mark_tainted(context_keys, source_kind="PARAMETER", source_name="context_keys")
    ad_html = f"<div class='ad-banner'>Sponsored Deal for <span>{tainted_context}</span>: 20% OFF Vintage Items!</div>"

    finding = check_xss_sink(ad_html, sink_signature="ad_svc.HTMLResponse")
    if finding:
        agent.event_buffer.append(finding)

    return {
        "service": "adservice",
        "context_keys": context_keys,
        "ad_html": ad_html,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.get("/api/ads/telemetry")
async def ping_telemetry(host: str = "127.0.0.1"):
    """Perform network ping diagnostic for ad server telemetry.
    
    Security Sink: OS Command Injection (CWE-78)
    """
    tainted_host = mark_tainted(host, source_kind="PARAMETER", source_name="host")
    cmd = f"ping -c 1 {tainted_host}"

    finding = check_command_sink(cmd, sink_signature="ad_svc.subprocess.Popen")
    if finding:
        agent.event_buffer.append(finding)

    return {
        "service": "adservice",
        "diagnostic_cmd": cmd,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8093)
