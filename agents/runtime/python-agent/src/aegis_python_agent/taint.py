"""Taint tracking engine for Python runtime agent.

Tracks untrusted data ranges (sources -> propagators -> sinks) using contextvars
for safe async/thread isolation.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TaintRange:
    start: int
    end: int
    source_kind: str
    source_name: str


@dataclass
class TaintRecord:
    value: str
    ranges: list[TaintRange] = field(default_factory=list)


# Contextvar storing active request trace information
_CURRENT_TRACE: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "_CURRENT_TRACE", default=None
)

# Registry of tainted string values (weak reference concept or string id mapping)
_TAINT_REGISTRY: dict[int, TaintRecord] = {}


def start_request_trace(trace_id: str, route: str, method: str) -> None:
    """Initialize request trace context for current async task/thread."""
    _CURRENT_TRACE.set({
        "trace_id": trace_id,
        "route": route,
        "method": method,
        "sources": [],
    })


def get_current_trace() -> dict[str, Any] | None:
    """Get active request trace context."""
    return _CURRENT_TRACE.get()


def clear_request_trace() -> None:
    """Clear request trace context."""
    _CURRENT_TRACE.set(None)


def mark_tainted(value: str, source_kind: str, source_name: str) -> str:
    """Mark a string value as tainted from a specific source."""
    if not value or not isinstance(value, str):
        return value

    tr = TaintRecord(
        value=value,
        ranges=[TaintRange(start=0, end=len(value), source_kind=source_kind, source_name=source_name)],
    )
    _TAINT_REGISTRY[id(value)] = tr

    trace = get_current_trace()
    if trace is not None:
        trace["sources"].append({"kind": source_kind, "name": source_name, "value": value[:100]})

    return value


def is_tainted(value: Any) -> tuple[bool, TaintRecord | None]:
    """Check whether a string value is registered as tainted."""
    if not isinstance(value, str):
        return False, None

    rec = _TAINT_REGISTRY.get(id(value))
    if rec is not None:
        return True, rec

    # Substring check fallback
    for val_id, record in list(_TAINT_REGISTRY.items())[-50:]:
        if record.value and record.value in value:
            return True, record

    return False, None
