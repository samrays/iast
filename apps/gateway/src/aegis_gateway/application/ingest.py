"""The ingest use case.

One batch in, one accounting record out. Everything expensive — correlation, dedup identity,
risk scoring — happens downstream in the worker. The gateway's entire job is to decide, fast,
whether an event is well-formed, whose it is, and whether the tenant may send it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..domain.errors import BatchTooLargeError, InvalidEventError, QuotaExceededError
from ..domain.events import EventType, RuntimeEvent, parse_event
from ..domain.ports import DeduplicationCache, EventSink, QuotaLimiter, StreamOrigin
from ..domain.quota import SheddingPolicy
from .context import AgentPrincipal


@dataclass(frozen=True, slots=True)
class Rejection:
    """One event the gateway refused, with enough context for an agent author to fix it."""

    line: int
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"line": self.line, "reason": self.reason}


@dataclass(slots=True)
class IngestResult:
    """What happened to a batch, reported back to the agent so it can advance its cursor."""

    accepted: int = 0
    duplicates: int = 0
    shed: int = 0
    rejected: int = 0
    #: Line numbers and reasons, so an agent author can fix a schema bug.
    rejections: list[Rejection] = field(default_factory=list)
    #: Highest event id durably accepted; the agent trims its spool up to this.
    ack_cursor: str = ""
    #: Events the gateway is willing to take before the next batch.
    credit: int = 0

    @property
    def processed(self) -> int:
        return self.accepted + self.duplicates + self.shed + self.rejected


class IngestEvents:
    """Validate, admit and publish one NDJSON batch."""

    def __init__(
        self,
        sink: EventSink,
        quota: QuotaLimiter,
        dedup: DeduplicationCache,
        *,
        max_batch_bytes: int,
        max_batch_events: int,
        shedding: SheddingPolicy | None = None,
        reject_batch_on_invalid: bool = False,
    ) -> None:
        self._sink = sink
        self._quota = quota
        self._dedup = dedup
        self._max_batch_bytes = max_batch_bytes
        self._max_batch_events = max_batch_events
        self._shedding = shedding or SheddingPolicy()
        # Default is lenient: one malformed event must not cost a tenant the other 511 in the
        # batch, several of which may be confirmed injections. Strict mode exists for agent
        # development, where silence about a schema bug is worse.
        self._reject_batch_on_invalid = reject_batch_on_invalid

    async def execute(self, principal: AgentPrincipal, body: bytes) -> IngestResult:
        if len(body) > self._max_batch_bytes:
            raise BatchTooLargeError(self._max_batch_bytes)

        result = IngestResult()
        publishable: list[RuntimeEvent] = []
        # Counts every non-blank line examined. `result.processed` cannot serve here:
        # `accepted` is only set after the publish, so using it would leave the batch limit
        # silently unenforced and let one request carry unbounded events.
        seen = 0

        for line_number, raw_line in enumerate(body.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            if seen >= self._max_batch_events:
                # Past the declared batch limit the agent is misbehaving; stop reading rather
                # than letting one request consume unbounded CPU.
                result.rejected += 1
                result.rejections.append(
                    Rejection(line_number, "batch event limit exceeded")
                )
                break

            seen += 1
            try:
                decoded = json.loads(stripped)
                event = parse_event(decoded, line_number)
            except json.JSONDecodeError as exc:
                self._record_rejection(result, line_number, f"malformed JSON: {exc.msg}")
                continue
            except InvalidEventError as exc:
                self._record_rejection(result, line_number, exc.reason)
                continue

            if self._dedup.seen(event.event_id):
                # The spool replays after every reconnect. Counting these as accepted would
                # inflate a tenant's findings on any flaky network.
                result.duplicates += 1
                result.ack_cursor = event.event_id
                continue

            cost = self._shedding.cost(event.type)
            remaining = self._quota.remaining_fraction(principal.organization_id)

            if not self._shedding.should_accept(event.type, remaining):
                result.shed += 1
                continue

            if not self._quota.check(principal.organization_id, cost):
                if event.type.is_security_signal:
                    # Over quota *and* it is a finding. Refusing the batch tells the agent to
                    # retry rather than lose it: security signal is never silently discarded.
                    raise QuotaExceededError(
                        self._quota.retry_after_seconds(principal.organization_id, cost)
                    )
                result.shed += 1
                continue

            self._dedup.remember(event.event_id)
            publishable.append(event)

        if self._reject_batch_on_invalid and result.rejections:
            first = result.rejections[0]
            raise InvalidEventError(first.reason, first.line)

        if publishable:
            # Raises SinkUnavailableError on failure, which surfaces as a retryable 503 and
            # leaves the events in the agent's spool.
            await self._sink.publish(
                StreamOrigin(
                    organization_id=principal.organization_id,
                    agent_id=principal.agent_id,
                    environment_id=principal.environment_id,
                ),
                publishable,
            )
            result.accepted = len(publishable)
            result.ack_cursor = publishable[-1].event_id

        result.credit = self._credit_for(principal)
        return result

    def _record_rejection(self, result: IngestResult, line: int, reason: str) -> None:
        result.rejected += 1
        # Bounded: a pathological agent sending 10k malformed lines must not make the response
        # larger than the request.
        if len(result.rejections) < 20:
            result.rejections.append(Rejection(line, reason))

    def _credit_for(self, principal: AgentPrincipal) -> int:
        """Credit-based backpressure.

        The agent throttles to this rather than being told to slow down after the fact, so a
        tenant approaching its ceiling degrades smoothly instead of hitting a wall of 429s.
        """
        remaining = self._quota.remaining_fraction(principal.organization_id)
        return max(1, int(self._max_batch_events * remaining))


def summarize_types(events: list[RuntimeEvent]) -> dict[str, int]:
    """Per-type counts, for metrics and the response body."""
    counts: dict[str, int] = {}
    for event in events:
        counts[event.type.value] = counts.get(event.type.value, 0) + 1
    return counts


__all__ = ["EventType", "IngestEvents", "IngestResult", "Rejection", "summarize_types"]
