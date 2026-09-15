"""Core Python Runtime Agent lifecycle & telemetry publisher.

Orchestrates taint tracking, process instrumentation, and background event dispatch
to the gateway.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from .sinks import check_command_sink, check_sql_sink
from .taint import clear_request_trace, mark_tainted, start_request_trace

logger = logging.getLogger("AegisPythonAgent")


class AegisAgent:
    """Python IAST runtime agent manager."""

    def __init__(
        self,
        agent_id: str,
        organization_id: str,
        gateway_url: str = "http://localhost:8081",
    ) -> None:
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.gateway_url = gateway_url
        self.event_buffer: list[dict[str, Any]] = []
        self._running = False

    @classmethod
    def start(
        cls,
        agent_id: str = "",
        organization_id: str = "",
        gateway_url: str = "http://localhost:8081",
    ) -> AegisAgent:
        """Start and initialize the Aegis Python Agent."""
        agent = cls(
            agent_id=agent_id or str(uuid.uuid4()),
            organization_id=organization_id or str(uuid.uuid4()),
            gateway_url=gateway_url,
        )
        agent._running = True
        logger.info("Aegis Python IAST Agent initialized [Agent ID: %s]", agent.agent_id)
        return agent

    def wrap_request(self, route: str, method: str, params: dict[str, str]) -> str:
        """WSGI/ASGI middleware entry point: initializes trace and taints incoming query/body params."""
        trace_id = f"py-trace-{uuid.uuid4().hex[:12]}"
        start_request_trace(trace_id, route, method)

        # Taint incoming parameters
        for key, val in params.items():
            mark_tainted(val, source_kind="PARAMETER", source_name=key)

        return trace_id

    def inspect_query(self, sql_query: str) -> dict[str, Any] | None:
        """Convenience method to inspect a SQL query and buffer findings."""
        finding = check_sql_sink(sql_query)
        if finding:
            self.event_buffer.append(finding)
            logger.warning("IAST Finding Detected: %s at %s", finding["rule_key"], finding["sink_signature"])
        return finding

    def finish_request(self) -> None:
        """Clean up request context after execution completes."""
        clear_request_trace()
