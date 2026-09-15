"""Unit tests for the ClickHouse telemetry client adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from aegis_api.infrastructure.clickhouse import ClickHouseClient, RuntimeEventDTO


@pytest.mark.asyncio
async def test_clickhouse_insert_empty_returns_zero() -> None:
    client = ClickHouseClient()
    count = await client.insert_runtime_events([])
    assert count == 0


@pytest.mark.asyncio
async def test_clickhouse_dto_construction() -> None:
    event_id = uuid4()
    org_id = uuid4()
    app_id = uuid4()
    agent_id = uuid4()
    now = datetime.now(timezone.utc)

    dto = RuntimeEventDTO(
        event_id=event_id,
        organization_id=org_id,
        application_id=app_id,
        environment="production",
        agent_id=agent_id,
        trace_id="trace-123",
        span_id="span-456",
        event_type="TAINT_HIT",
        rule_key="sql-injection",
        severity="CRITICAL",
        confidence=0.95,
        route_method="POST",
        route_path="/api/login",
        source_kind="PARAMETER",
        sink_signature="java.sql.Statement#executeQuery",
        stack_fingerprint="fingerprint-abc",
        taint_path='{"nodes": []}',
        request_summary='{"user_agent": "curl/7.68.0"}',
        source_ip="127.0.0.1",
        duration_us=1500,
        occurred_at=now,
    )

    assert dto.event_id == event_id
    assert dto.organization_id == org_id
    assert dto.rule_key == "sql-injection"
    assert dto.severity == "CRITICAL"
