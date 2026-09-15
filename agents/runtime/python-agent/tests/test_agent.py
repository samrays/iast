"""Unit tests for Aegis Python IAST Agent."""

from __future__ import annotations

import pytest
from aegis_python_agent import AegisAgent, check_sql_sink, mark_tainted


def test_agent_initialization() -> None:
    agent = AegisAgent.start(agent_id="test-agent-1", organization_id="test-org-1")
    assert agent.agent_id == "test-agent-1"
    assert agent.organization_id == "test-org-1"


def test_taint_tracking_and_sql_sink_detection() -> None:
    agent = AegisAgent.start()

    # Wrap request & taint input parameter
    agent.wrap_request(route="/users/search", method="GET", params={"user_id": "1 OR 1=1"})

    # Construct unparameterized query using the tainted value
    user_input = "1 OR 1=1"
    tainted_param = mark_tainted(user_input, source_kind="PARAMETER", source_name="user_id")
    raw_query = f"SELECT * FROM users WHERE id = {tainted_param}"

    # Inspect query
    finding = agent.inspect_query(raw_query)

    assert finding is not None
    assert finding["rule_key"] == "sql-injection"
    assert finding["severity"] == "CRITICAL"
    assert "SELECT * FROM users WHERE id = 1 OR 1=1" in finding["sink_argument"]

    agent.finish_request()


def test_safe_untainted_query_produces_no_finding() -> None:
    agent = AegisAgent.start()
    agent.wrap_request(route="/users/me", method="GET", params={})

    safe_query = "SELECT * FROM users WHERE id = 42"
    finding = check_sql_sink(safe_query)

    assert finding is None
    agent.finish_request()
