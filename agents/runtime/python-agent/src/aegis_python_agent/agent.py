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
        protection_mode: str = "MONITOR",
    ) -> None:
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.gateway_url = gateway_url
        self.protection_mode = protection_mode.upper()
        self.event_buffer: list[dict[str, Any]] = []
        self._running = False

    @classmethod
    def start(
        cls,
        agent_id: str = "",
        organization_id: str = "",
        gateway_url: str = "http://localhost:8081",
        protection_mode: str = "MONITOR",
        auto_instrument: bool = False,
    ) -> AegisAgent:
        """Start and initialize the Aegis Python Agent."""
        agent = cls(
            agent_id=agent_id or str(uuid.uuid4()),
            organization_id=organization_id or str(uuid.uuid4()),
            gateway_url=gateway_url,
            protection_mode=protection_mode,
        )
        agent._running = True
        if auto_instrument:
            from .hooking import hook_all_sinks
            hook_all_sinks(agent)
        logger.info(
            "Aegis Python IAST Agent initialized [Agent ID: %s, Mode: %s]",
            agent.agent_id,
            agent.protection_mode,
        )
        return agent

    def set_protection_mode(self, mode: str) -> None:
        """Dynamically switch between MONITOR and BLOCK modes."""
        self.protection_mode = mode.upper()
        logger.info("Aegis ADR Protection Mode updated to: %s", self.protection_mode)

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
