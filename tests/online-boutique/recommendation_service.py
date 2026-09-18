"""Google Online Boutique - Recommendation Microservice.

Instrumented with Aegis IAST Python Agent to monitor product recommendations,
category searches (SQL Injection - CWE-89), and catalog asset reading (Path Traversal - CWE-22).
"""

from __future__ import annotations

import logging
import os
import sqlite3
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
    check_path_traversal_sink,
    check_sql_sink,
    mark_tainted,
)

logger = logging.getLogger("recommendation_service")

# Initialize Aegis Agent for Recommendation Service
agent = AegisAgent.start(
    agent_id="online-boutique-recommendation-svc-agent",
    organization_id="00000000-0000-0000-0000-000000000001",
)

app = FastAPI(title="Google Online Boutique - Recommendation Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup SQLite Database for Product Recommendations Catalog
conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE products (id TEXT PRIMARY KEY, name TEXT, category TEXT, price REAL);")
cursor.execute(
    "INSERT INTO products (id, name, category, price) VALUES "
    "('OLJ3925781', 'Vintage Typewriter', 'vintage', 67.99), "
    "('66VCHS25TF', 'Vintage Camera Lens', 'vintage', 12.49), "
    "('1YHVB1424E', 'Barista Kit', 'cookware', 49.99), "
    "('L9ECAV2K07', 'Air Plant Terrarium', 'gardening', 12.99);"
)
conn.commit()


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
            "service": "recommendationservice",
            "iast_finding_detected": True,
        },
    )


@app.get("/api/protection-mode")
async def get_protection_mode():
    return {"service": "recommendationservice", "mode": agent.protection_mode}


@app.post("/api/protection-mode")
async def set_protection_mode(payload: dict):
    mode = payload.get("mode", "MONITOR").upper()
    agent.set_protection_mode(mode)
    return {"service": "recommendationservice", "mode": agent.protection_mode}


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


@app.get("/api/recommendations")
async def get_recommendations(category: str = "vintage"):
    """Fetch product recommendations using secure parameterized query.
    
    Benign operational endpoint.
    """
    query = "SELECT id, name, category, price FROM products WHERE category = ?"
    cursor.execute(query, (category,))
    rows = cursor.fetchall()
    products = [{"id": r[0], "name": r[1], "category": r[2], "price": r[3]} for r in rows]
    finding = check_sql_sink(query, sink_signature="recommendation_svc.sqlite3.execute")
    if finding:
        agent.event_buffer.append(finding)

    return {
        "service": "recommendationservice",
        "category": category,
        "recommendations": products,
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


@app.get("/api/recommendations/raw_search")
async def get_recommendations_raw(category: str = "vintage"):
    """Fetch product recommendations using un-parameterized SQL formatting.
    
    Security Sink: SQL Injection (CWE-89)
    """
    tainted_category = mark_tainted(category, source_kind="PARAMETER", source_name="category")
    query = f"SELECT id, name, category, price FROM products WHERE category = '{tainted_category}'"
    finding = check_sql_sink(query, sink_signature="recommendation_svc.sqlite3.execute")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked SQL Injection execution attempt before database query execution.",
                rule_key="sql-injection",
                sink_signature="recommendation_svc.sqlite3.execute",
            )

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        products = [{"id": r[0], "name": r[1], "category": r[2], "price": r[3]} for r in rows]
        return {
            "service": "recommendationservice",
            "category": category,
            "recommendations": products,
            "iast_finding_detected": finding is not None,
            "finding": finding,
        }
    except AegisSecurityBlockException:
        raise
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "service": "recommendationservice",
                "error": str(exc),
                "query": query,
                "iast_finding_detected": finding is not None,
                "finding": finding,
            },
        )


@app.get("/api/recommendations/catalog")
async def get_catalog_asset(asset_name: str = "banner.png"):
    """Fetch product catalog media/spec asset by filename.
    
    Security Sink: Path Traversal (CWE-22)
    """
    tainted_asset = mark_tainted(asset_name, source_kind="PARAMETER", source_name="asset_name")
    finding = check_path_traversal_sink(tainted_asset, sink_signature="recommendation_svc.open_asset")
    if finding:
        agent.event_buffer.append(finding)
        if agent.protection_mode == "BLOCK":
            raise AegisSecurityBlockException(
                "Blocked Path Traversal attempt targeting system filesystem.",
                rule_key="path-traversal",
                sink_signature="recommendation_svc.open_asset",
            )

    return {
        "service": "recommendationservice",
        "asset_name": asset_name,
        "asset_status": "loaded",
        "iast_finding_detected": finding is not None,
        "finding": finding,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8091)
