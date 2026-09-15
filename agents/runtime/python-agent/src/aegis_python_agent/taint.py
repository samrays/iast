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


class TaintedString(str):
    """String wrapper preserving taint attributes across C-extension boundaries."""
    __slots__ = ("taint_record",)

    def __new__(cls, value: str, record: TaintRecord) -> TaintedString:
        instance = super().__new__(cls, value)
        instance.taint_record = record
        return instance


def mark_tainted(value: str, source_kind: str, source_name: str) -> str:
    """Mark a string value as tainted from a specific source."""
    if not value or not isinstance(value, str):
        return value

    tr = TaintRecord(
        value=value,
        ranges=[TaintRange(start=0, end=len(value), source_kind=source_kind, source_name=source_name)],
    )
    
    # Wrap string to preserve taint across compiled C-extensions
    wrapped = TaintedString(value, tr)
    _TAINT_REGISTRY[id(value)] = tr
    _TAINT_REGISTRY[id(wrapped)] = tr

    trace = get_current_trace()
    if trace is not None:
        trace["sources"].append({"kind": source_kind, "name": source_name, "value": value[:100]})

    return wrapped


def is_tainted(value: Any) -> tuple[bool, TaintRecord | None]:
    """Check whether a string value is registered as tainted.
    
    Enforces request-scoped context verification so static configuration constants
    loaded outside active request traces are not falsely flagged.
    """
    if not isinstance(value, str):
        return False, None

    # Check direct TaintedString wrapper attribute
    if hasattr(value, "taint_record") and getattr(value, "taint_record") is not None:
        return True, getattr(value, "taint_record")

    # Check object id in registry
    rec = _TAINT_REGISTRY.get(id(value))
    if rec is not None:
        return True, rec

    # Substring check fallback: only evaluate when an active request trace is active
    # and the tainted value length is at least 3 characters to prevent static constant FPs
    trace = get_current_trace()
    if trace is not None:
        for val_id, record in list(_TAINT_REGISTRY.items())[-50:]:
            if record.value and len(record.value) >= 3 and record.value in value:
                return True, record

    return False, None
