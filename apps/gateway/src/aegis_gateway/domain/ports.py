"""Ports the gateway depends on.

``typing.Protocol`` again, so adapters satisfy them structurally and tests can substitute
in-memory doubles without inheritance (ADR-0002).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .events import RuntimeEvent


@runtime_checkable
class Clock(Protocol):
    def monotonic(self) -> float: ...

    def now_ms(self) -> int: ...


@runtime_checkable
class AgentPrincipalLike(Protocol):
    @property
    def agent_id(self) -> str: ...

    @property
    def organization_id(self) -> str: ...


@runtime_checkable
class AgentAuthenticator(Protocol):
    """Verifies an agent credential.

    Deliberately synchronous and stateless: verification is a signature check, not a database
    lookup. That is what lets the gateway scale horizontally without the control plane's
    database becoming the ingest bottleneck (docs/01 §3).
    """

    def authenticate(self, credential: str) -> AgentPrincipalLike: ...


@runtime_checkable
class EventSink(Protocol):
    """The durable stream events are handed to.

    Kafka in production; a file or an in-memory buffer locally and in tests. Keeping this a
    port means an outage of the stream is a swappable adapter concern rather than a rewrite.
    """

    async def publish(self, organization_id: str, events: list[RuntimeEvent]) -> None:
        """Publish a batch.

        Raise :class:`~aegis_gateway.domain.errors.SinkUnavailableError` to tell the agent to
        keep the batch in its spool. Returning normally means durably accepted.
        """
        ...

    async def close(self) -> None: ...


@runtime_checkable
class QuotaLimiter(Protocol):
    """Per-tenant admission control."""

    def check(self, organization_id: str, cost: float) -> bool: ...

    def remaining_fraction(self, organization_id: str) -> float: ...

    def retry_after_seconds(self, organization_id: str, cost: float) -> int: ...


@runtime_checkable
class DeduplicationCache(Protocol):
    """Remembers recently seen event ids.

    The agent transport is at-least-once — it replays its spool after a reconnect — so the
    gateway must be idempotent or every network blip inflates a tenant's findings.
    """

    def seen(self, event_id: str) -> bool: ...

    def remember(self, event_id: str) -> None: ...
