"""ClickHouse telemetry store adapter.

Provides HTTP-based ingestion and analytics queries over the ClickHouse cluster.
Events (TAINT_HIT, ATTACK, ROUTE, METRIC) land in ClickHouse for high-throughput
search, visualization rollups, and SIEM streaming.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence
from uuid import UUID

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuntimeEventDTO:
    event_id: UUID
    organization_id: UUID
    application_id: UUID
    environment: str
    agent_id: UUID
    trace_id: str
    span_id: str
    event_type: str
    rule_key: str
    severity: str
    confidence: float
    route_method: str
    route_path: str
    source_kind: str
    sink_signature: str
    stack_fingerprint: str
    taint_path: str
    request_summary: str
    source_ip: str
    duration_us: int
    occurred_at: datetime


class ClickHouseClient:
    """Async HTTP client for ClickHouse event ingestion and analytics queries."""

    def __init__(
        self,
        url: str = "http://localhost:8123",
        database: str = "default",
        user: str = "default",
        password: str = "",
        timeout_seconds: float = 10.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.database = database
        self.user = user
        self.password = password
        self.timeout_seconds = timeout_seconds

    async def execute_ddl(self, sql_script: str) -> bool:
        """Execute DDL statements against the ClickHouse cluster."""
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            headers = {}
            if self.user:
                headers["X-ClickHouse-User"] = self.user
            if self.password:
                headers["X-ClickHouse-Key"] = self.password

            params = {"database": self.database}
            
            # Split DDL by semicolons to execute clean statements
            statements = [s.strip() for s in sql_script.split(";") if s.strip()]
            for stmt in statements:
                resp = await client.post(self.url, content=stmt, params=params, headers=headers)
                if resp.status_code != 200:
                    logger.error("ClickHouse DDL error (%d): %s", resp.status_code, resp.text)
                    return False
            return True

    async def insert_runtime_events(self, events: Sequence[RuntimeEventDTO]) -> int:
        """Batch insert runtime events into ClickHouse."""
        if not events:
            return 0

        # Construct JSONEachRow payload
        rows = []
        for e in events:
            rows.append({
                "event_id": str(e.event_id),
                "organization_id": str(e.organization_id),
                "application_id": str(e.application_id),
                "environment": e.environment,
                "agent_id": str(e.agent_id),
                "trace_id": e.trace_id,
                "span_id": e.span_id,
                "event_type": e.event_type,
                "rule_key": e.rule_key,
                "severity": e.severity,
                "confidence": e.confidence,
                "route_method": e.route_method,
                "route_path": e.route_path,
                "source_kind": e.source_kind,
                "sink_signature": e.sink_signature,
                "stack_fingerprint": e.stack_fingerprint,
                "taint_path": e.taint_path,
                "request_summary": e.request_summary,
                "source_ip": e.source_ip,
                "duration_us": e.duration_us,
                "occurred_at": e.occurred_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            })

        query = f"INSERT INTO {self.database}.runtime_events FORMAT JSONEachRow"
        body = "\n".join([httpx.Response(200, json=r).text for r in rows]) # Serialized JSON lines

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            headers = {}
            if self.user:
                headers["X-ClickHouse-User"] = self.user
            if self.password:
                headers["X-ClickHouse-Key"] = self.password

            resp = await client.post(
                self.url,
                params={"query": query, "database": self.database},
                content=body,
                headers=headers,
            )
            if resp.status_code == 200:
                return len(events)
            
            logger.error("ClickHouse insert failed (%d): %s", resp.status_code, resp.text)
            return 0

    async def query(self, sql_query: str) -> list[dict[str, Any]]:
        """Run a SELECT query and return result rows as dictionaries."""
        query_with_format = f"{sql_query.rstrip(';')} FORMAT JSON"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            headers = {}
            if self.user:
                headers["X-ClickHouse-User"] = self.user
            if self.password:
                headers["X-ClickHouse-Key"] = self.password

            resp = await client.post(
                self.url,
                params={"database": self.database},
                content=query_with_format,
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", []) # type: ignore[no-any-return]
            
            logger.error("ClickHouse query error (%d): %s", resp.status_code, resp.text)
            return []
