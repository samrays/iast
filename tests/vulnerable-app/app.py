"""Self-contained OWASP Top 10 vulnerable test application instrumented with Aegis Python IAST Agent.

Exposes security-sensitive endpoints to demonstrate real-time taint tracking across 10 OWASP categories:
1. GET /api/users/search?name=... (SQL Injection - CWE-89)
2. GET /api/system/ping?host=... (OS Command Injection - CWE-78)
3. POST /api/data/deserialize (Unsafe Deserialization - CWE-502)
4. POST /api/xml/parse (XML External Entity XXE - CWE-611)
5. GET /api/files/read?filename=... (Path Traversal - CWE-22)
6. GET /api/render/html?user_input=... (Reflected XSS - CWE-79)
7. GET /api/fetch/url?target=... (Server-Side Request Forgery SSRF - CWE-918)
8. GET /api/navigate/redirect?url=... (Open Redirect - CWE-601)
9. GET /api/headers/set?custom_header=... (HTTP Header Injection - CWE-113)
10. GET /api/system/log?msg=... (Log Injection - CWE-117)
"""

from __future__ import annotations

import logging
import os
import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from aegis_python_agent import (
    AegisAgent,
    check_command_sink,
    check_deserialization_sink,
    check_header_injection_sink,
    check_log_injection_sink,
    check_open_redirect_sink,
    check_path_traversal_sink,
    check_sql_sink,
    check_ssrf_sink,
    check_xss_sink,
    check_xxe_sink,
    mark_tainted,
)

logger = logging.getLogger("vulnerable_app")

# Initialize Aegis IAST Runtime Agent
agent = AegisAgent.start(
    agent_id="owasp-top10-vulnerable-app-agent-01",
    organization_id="00000000-0000-0000-0000-000000000001",
)

app = FastAPI(title="Aegis IAST OWASP Top 10 Vulnerable Test Application")

# In-memory SQLite database setup
conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT);")
cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'ADMINISTRATOR'), ('alice', 'USER');")
conn.commit()


@app.middleware("http")
async def aegis_iast_middleware(request: Request, call_next):
    """Middleware: Initializes request trace context & taints incoming HTTP query parameters."""
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


# 1. SQL Injection (CWE-89)
@app.get("/api/users/search")
async def search_users(name: str = ""):
    tainted_name = mark_tainted(name, source_kind="PARAMETER", source_name="name")
    query = f"SELECT id, username, role FROM users WHERE username = '{tainted_name}'"
    finding = check_sql_sink(query)
    if finding:
        agent.event_buffer.append(finding)

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return {"query_executed": query, "results": rows, "iast_finding_detected": finding is not None, "finding": finding}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc), "query": query, "iast_finding_detected": finding is not None, "finding": finding})


# 2. OS Command Injection (CWE-78)
@app.get("/api/system/ping")
async def ping_host(host: str = "127.0.0.1"):
    tainted_host = mark_tainted(host, source_kind="PARAMETER", source_name="host")
    cmd = f"ping -c 1 {tainted_host}"
    finding = check_command_sink(cmd)
    if finding:
        agent.event_buffer.append(finding)
    return {"command": cmd, "iast_finding_detected": finding is not None, "finding": finding}


# 3. Unsafe Deserialization (CWE-502)
@app.post("/api/data/deserialize")
async def deserialize_payload(request: Request):
    body = await request.body()
    body_str = body.decode("utf-8", errors="ignore")
    tainted_data = mark_tainted(body_str, source_kind="BODY", source_name="payload")
    finding = check_deserialization_sink(tainted_data)
    if finding:
        agent.event_buffer.append(finding)
    return {"payload": body_str, "iast_finding_detected": finding is not None, "finding": finding}


# 4. XML External Entity (XXE) Injection (CWE-611)
@app.post("/api/xml/parse")
async def parse_xml(request: Request):
    body = await request.body()
    body_str = body.decode("utf-8", errors="ignore")
    tainted_xml = mark_tainted(body_str, source_kind="BODY", source_name="xml")
    finding = check_xxe_sink(tainted_xml)
    if finding:
        agent.event_buffer.append(finding)
    return {"xml": body_str, "iast_finding_detected": finding is not None, "finding": finding}


# 5. Path Traversal (CWE-22)
@app.get("/api/files/read")
async def read_file(filename: str = ""):
    tainted_file = mark_tainted(filename, source_kind="PARAMETER", source_name="filename")
    finding = check_path_traversal_sink(tainted_file)
    if finding:
        agent.event_buffer.append(finding)
    return {"filename": tainted_file, "iast_finding_detected": finding is not None, "finding": finding}


# 6. Reflected Cross-Site Scripting (XSS) (CWE-79)
@app.get("/api/render/html")
async def render_html(user_input: str = ""):
    tainted_input = mark_tainted(user_input, source_kind="PARAMETER", source_name="user_input")
    html_content = f"<div>Welcome, {tainted_input}!</div>"
    finding = check_xss_sink(html_content)
    if finding:
        agent.event_buffer.append(finding)
    return {"rendered": html_content, "iast_finding_detected": finding is not None, "finding": finding}


# 7. Server-Side Request Forgery (SSRF) (CWE-918)
@app.get("/api/fetch/url")
async def fetch_url(target: str = ""):
    tainted_target = mark_tainted(target, source_kind="PARAMETER", source_name="target")
    finding = check_ssrf_sink(tainted_target)
    if finding:
        agent.event_buffer.append(finding)
    return {"target_url": tainted_target, "iast_finding_detected": finding is not None, "finding": finding}


# 8. Open Redirect (CWE-601)
@app.get("/api/navigate/redirect")
async def navigate_redirect(url: str = ""):
    tainted_url = mark_tainted(url, source_kind="PARAMETER", source_name="url")
    finding = check_open_redirect_sink(tainted_url)
    if finding:
        agent.event_buffer.append(finding)
    return {"redirect_url": tainted_url, "iast_finding_detected": finding is not None, "finding": finding}


# 9. HTTP Header Injection (CWE-113)
@app.get("/api/headers/set")
async def set_custom_header(custom_header: str = ""):
    tainted_header = mark_tainted(custom_header, source_kind="PARAMETER", source_name="custom_header")
    finding = check_header_injection_sink(tainted_header)
    if finding:
        agent.event_buffer.append(finding)
    return {"header_value": tainted_header, "iast_finding_detected": finding is not None, "finding": finding}


# 10. Log Injection (CWE-117)
@app.get("/api/system/log")
async def log_event(msg: str = ""):
    tainted_msg = mark_tainted(msg, source_kind="PARAMETER", source_name="msg")
    finding = check_log_injection_sink(tainted_msg)
    if finding:
        agent.event_buffer.append(finding)
    return {"log_message": tainted_msg, "iast_finding_detected": finding is not None, "finding": finding}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8095)
