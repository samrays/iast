"""Keyset (cursor) pagination helpers.

Offset pagination is not offered anywhere in the API: on a live table it both degrades as
the offset grows and silently duplicates or skips rows when data changes between pages.
A cursor over ``(created_at, id)`` is stable and index-friendly.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from ...domain.errors import ValidationError


def encode_cursor(created_at: datetime, row_id: UUID) -> str:
    payload = {"t": created_at.astimezone(UTC).isoformat(), "i": str(row_id)}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    """Decode a cursor, rejecting anything malformed.

    A cursor is opaque to clients but is not a secret and is not trusted: it is validated
    like any other input, because it lands in a WHERE clause.
    """
    try:
        padding = "=" * (-len(cursor) % 4)
        payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(cursor + padding))
        timestamp = datetime.fromisoformat(str(payload["t"]))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return timestamp, UUID(str(payload["i"]))
    except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
        raise ValidationError("The pagination cursor is not valid.", field="cursor") from exc


def encode_score_cursor(score: float, row_id: UUID) -> str:
    """A cursor for a list ordered by score rather than by time.

    The row id is part of it, not decoration: many findings share a score, and a cursor that
    carried only the score would skip or repeat every row it tied with.
    """
    payload = {"s": float(score), "i": str(row_id)}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_score_cursor(cursor: str) -> tuple[float, UUID]:
    try:
        padding = "=" * (-len(cursor) % 4)
        payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(cursor + padding))
        return float(payload["s"]), UUID(str(payload["i"]))
    except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
        raise ValidationError("The pagination cursor is not valid.", field="cursor") from exc


def clamp_limit(limit: int | None, *, default: int, maximum: int) -> int:
    if limit is None:
        return default
    if limit < 1:
        raise ValidationError("limit must be at least 1.", field="limit")
    return min(limit, maximum)
