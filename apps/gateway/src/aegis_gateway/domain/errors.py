"""Gateway domain errors.

Mapped to HTTP once, at the interface boundary, exactly as in the control-plane API
(ADR-0002). Nothing below the interface layer knows a status code exists.
"""

from __future__ import annotations

from typing import Any


class GatewayError(Exception):
    code = "gateway_error"
    message = "The gateway could not process this request."

    def __init__(self, message: str | None = None, **context: Any) -> None:
        self.message = message or self.message
        self.context: dict[str, Any] = context
        super().__init__(self.message)


class AgentAuthenticationError(GatewayError):
    """The presented agent credential is missing, malformed, expired or not an agent token."""

    code = "invalid_agent_credential"
    message = "A valid agent credential is required."


class AgentDisabledError(GatewayError):
    """The control plane has remotely disabled this agent (the kill switch)."""

    code = "agent_disabled"
    message = "This agent has been disabled."


class InvalidEventError(GatewayError):
    """A single event failed schema validation.

    Carries the offending line number so an agent author can find it, but never echoes the
    payload back — the payload is attacker-controlled and would land in the agent's logs.
    """

    code = "invalid_event"
    message = "The event did not match the wire schema."

    def __init__(self, reason: str, line: int) -> None:
        super().__init__(f"line {line}: {reason}", line=line, reason=reason)
        self.line = line
        self.reason = reason


class BatchTooLargeError(GatewayError):
    code = "batch_too_large"
    message = "The batch exceeds the maximum accepted size."

    def __init__(self, limit_bytes: int) -> None:
        super().__init__(f"Batches may be at most {limit_bytes} bytes.", limit_bytes=limit_bytes)


class QuotaExceededError(GatewayError):
    """The tenant has spent its ingest allowance for this window."""

    code = "quota_exceeded"
    message = "Ingest quota exceeded."

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(retry_after_seconds=retry_after_seconds)
        self.retry_after_seconds = retry_after_seconds


class SinkUnavailableError(GatewayError):
    """The durable stream rejected the batch.

    Surfaced as a retryable failure so the agent keeps the events in its spool rather than
    treating them as delivered.
    """

    code = "sink_unavailable"
    message = "The event stream is temporarily unavailable."
