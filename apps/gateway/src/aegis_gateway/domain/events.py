"""The runtime event envelope, validated at the edge.

Hand-written validation rather than Pydantic: the domain layer may not depend on a
serialization library (ADR-0002), and this code sits on the hottest path in the platform —
100k events/sec per replica — where a permissive parser is both a performance cost and a
security one.

Everything arriving here is attacker-influenced. A taint trace *contains the exact payload an
attacker sent*, so the parser assumes hostility: it bounds every string, rejects unknown
event types, and never evaluates or interpolates a field value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .errors import InvalidEventError

#: Caps on individual fields. Generous enough for real traces, small enough that a malicious
#: agent cannot make one event consume a meaningful fraction of a replica's memory.
MAX_ID_LENGTH = 64
MAX_STRING_LENGTH = 8_192
MAX_ARGUMENT_LENGTH = 65_536
MAX_STACK_FRAMES = 64
MAX_RANGES = 64


class EventType(StrEnum):
    TAINT_HIT = "EVENT_TYPE_TAINT_HIT"
    ATTACK = "EVENT_TYPE_ATTACK"
    ROUTE = "EVENT_TYPE_ROUTE"
    DEPENDENCY = "EVENT_TYPE_DEPENDENCY"
    CONFIG = "EVENT_TYPE_CONFIG"
    COVERAGE_GAP = "EVENT_TYPE_COVERAGE_GAP"

    @property
    def is_security_signal(self) -> bool:
        """True for events that must never be shed under backpressure.

        Dropping a finding to save capacity would mean the platform silently failed at the
        one job it exists to do. Inventory and coverage telemetry can wait; a confirmed
        injection cannot.
        """
        return self in (EventType.TAINT_HIT, EventType.ATTACK)


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """One validated event, ready to publish."""

    event_id: str
    type: EventType
    occurred_at_ms: int
    monotonic_nanos: int
    trace_id: str
    replayed: bool
    #: The already-validated payload, kept as a mapping. The gateway does not interpret
    #: finding semantics — that is the worker's job in Phase 5.
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def partition_key(self) -> str:
        """Kafka partition key.

        Keyed by trace so every event from one request lands on one partition and the worker
        can assemble a trace without a cross-partition join. Falls back to the event id so a
        traceless event still distributes evenly instead of hot-spotting partition zero.
        """
        return self.trace_id or self.event_id


def _require_str(
    raw: dict[str, Any], key: str, line: int, *, max_length: int, required: bool = True
) -> str:
    value = raw.get(key)
    if value is None:
        if required:
            raise InvalidEventError(f"missing {key!r}", line)
        return ""
    if not isinstance(value, str):
        raise InvalidEventError(f"{key!r} must be a string", line)
    if len(value) > max_length:
        raise InvalidEventError(f"{key!r} exceeds {max_length} characters", line)
    return value


def _require_int(raw: dict[str, Any], key: str, line: int, *, default: int | None = None) -> int:
    value = raw.get(key, default)
    if value is None:
        raise InvalidEventError(f"missing {key!r}", line)
    # bool is an int subclass in Python, and accepting `true` where a timestamp belongs is
    # exactly the kind of quiet type confusion that produces nonsense downstream.
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidEventError(f"{key!r} must be an integer", line)
    return value


def parse_event(raw: Any, line: int) -> RuntimeEvent:
    """Validate one decoded JSON object into a :class:`RuntimeEvent`.

    Raises :class:`InvalidEventError` with the line number; the caller decides whether one
    bad event rejects the batch or is simply counted.
    """
    if not isinstance(raw, dict):
        raise InvalidEventError("event must be a JSON object", line)

    event_id = _require_str(raw, "event_id", line, max_length=MAX_ID_LENGTH)
    if not event_id.strip():
        raise InvalidEventError("'event_id' must not be blank", line)

    type_name = _require_str(raw, "type", line, max_length=MAX_ID_LENGTH)
    try:
        event_type = EventType(type_name)
    except ValueError:
        # Unknown types are rejected, not ignored. A newer agent sending a type this gateway
        # does not understand should be visible, not silently dropped into a black hole.
        raise InvalidEventError(f"unknown event type {type_name!r}", line) from None

    occurred_at_ms = _require_int(raw, "occurred_at_ms", line)
    if occurred_at_ms <= 0:
        raise InvalidEventError("'occurred_at_ms' must be positive", line)

    monotonic_nanos = _require_int(raw, "monotonic_nanos", line, default=0)
    trace_id = _require_str(raw, "trace_id", line, max_length=MAX_ID_LENGTH, required=False)

    replayed_raw = raw.get("replayed", False)
    if not isinstance(replayed_raw, bool):
        raise InvalidEventError("'replayed' must be a boolean", line)

    payload = _extract_payload(raw, event_type, line)

    return RuntimeEvent(
        event_id=event_id,
        type=event_type,
        occurred_at_ms=occurred_at_ms,
        monotonic_nanos=monotonic_nanos,
        trace_id=trace_id,
        replayed=replayed_raw,
        payload=payload,
    )


#: Wire key carrying each event type's payload, mirroring the protobuf `oneof`.
_PAYLOAD_KEYS: dict[EventType, str] = {
    EventType.TAINT_HIT: "taint_hit",
    EventType.ATTACK: "attack",
    EventType.ROUTE: "route",
    EventType.DEPENDENCY: "dependency",
    EventType.CONFIG: "config_finding",
    EventType.COVERAGE_GAP: "coverage_gap",
}


def _extract_payload(raw: dict[str, Any], event_type: EventType, line: int) -> dict[str, Any]:
    key = _PAYLOAD_KEYS[event_type]
    payload = raw.get(key)
    if payload is None:
        raise InvalidEventError(f"missing {key!r} payload for {event_type.value}", line)
    if not isinstance(payload, dict):
        raise InvalidEventError(f"{key!r} must be an object", line)

    if event_type is EventType.TAINT_HIT:
        _validate_taint_hit(payload, line)
    return payload


def _validate_taint_hit(payload: dict[str, Any], line: int) -> None:
    """Check the fields the worker cannot function without.

    Deliberately shallow. The gateway's job is to reject nonsense cheaply and hand everything
    else on; deep semantic validation belongs in the worker where it can be done once, off
    the hot path.
    """
    _require_str(payload, "rule_key", line, max_length=MAX_ID_LENGTH)
    _require_str(payload, "sink_signature", line, max_length=MAX_STRING_LENGTH)
    _require_str(payload, "stack_fingerprint", line, max_length=MAX_ID_LENGTH)
    _require_str(payload, "sink_argument", line, max_length=MAX_ARGUMENT_LENGTH, required=False)

    ranges = payload.get("ranges", [])
    if not isinstance(ranges, list):
        raise InvalidEventError("'ranges' must be a list", line)
    if len(ranges) > MAX_RANGES:
        raise InvalidEventError(f"'ranges' exceeds {MAX_RANGES} entries", line)
    for entry in ranges:
        if not isinstance(entry, dict):
            raise InvalidEventError("each range must be an object", line)
        start = entry.get("start")
        length = entry.get("length")
        if isinstance(start, bool) or not isinstance(start, int) or start < 0:
            raise InvalidEventError("range 'start' must be a non-negative integer", line)
        if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
            raise InvalidEventError("range 'length' must be a positive integer", line)

    stack = payload.get("stack", [])
    if not isinstance(stack, list):
        raise InvalidEventError("'stack' must be a list", line)
    if len(stack) > MAX_STACK_FRAMES:
        raise InvalidEventError(f"'stack' exceeds {MAX_STACK_FRAMES} frames", line)
