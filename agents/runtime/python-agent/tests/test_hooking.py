"""Unit tests for transparent runtime hooking and ADR blocking."""

from __future__ import annotations

import sqlite3
import pytest

from aegis_python_agent import (
    AegisAgent,
    AegisSecurityBlockException,
    hook_sqlite3,
    mark_tainted,
)


def test_protection_mode_toggle():
    agent = AegisAgent.start(agent_id="test-adr-agent", protection_mode="MONITOR")
    assert agent.protection_mode == "MONITOR"
    agent.set_protection_mode("BLOCK")
    assert agent.protection_mode == "BLOCK"
    agent.set_protection_mode("MONITOR")
    assert agent.protection_mode == "MONITOR"


def test_sqlite3_hook_monitor_mode():
    agent = AegisAgent.start(agent_id="test-mon-agent", protection_mode="MONITOR")
    hook_sqlite3(agent)

    agent.wrap_request(route="/items", method="GET", params={})
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE items (id INT, val TEXT);")
        cursor.execute("INSERT INTO items VALUES (1, 'apple');")

        tainted_param = mark_tainted("apple' OR '1'='1", source_kind="PARAMETER", source_name="val")
        raw_query = f"SELECT * FROM items WHERE val = '{tainted_param}';"

        # In MONITOR mode, execute succeeds and findings are buffered
        cursor.execute(raw_query)
        rows = cursor.fetchall()
        assert len(rows) == 1
        assert any(ev["rule_key"] == "sql-injection" for ev in agent.event_buffer)
    finally:
        agent.finish_request()


def test_sqlite3_hook_block_mode():
    agent = AegisAgent.start(agent_id="test-blk-agent", protection_mode="BLOCK")
    hook_sqlite3(agent)

    agent.wrap_request(route="/items", method="GET", params={})
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE items (id INT, val TEXT);")

        # Safe untainted query should NOT be blocked
        cursor.execute("SELECT * FROM items WHERE id = 1;")

        # Tainted query should be intercepted and raise AegisSecurityBlockException
        tainted_param = mark_tainted("admin' --", source_kind="PARAMETER", source_name="username")
        malicious_query = f"SELECT * FROM items WHERE val = '{tainted_param}';"

        with pytest.raises(AegisSecurityBlockException) as exc_info:
            cursor.execute(malicious_query)

        assert "Blocked SQL Injection" in str(exc_info.value)
        assert exc_info.value.rule_key == "sql-injection"
        assert exc_info.value.sink_signature == "sqlite3.Cursor.execute"
    finally:
        agent.finish_request()

