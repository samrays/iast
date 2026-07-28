"""Clock adapters."""

from __future__ import annotations

from datetime import UTC, datetime


class SystemClock:
    """Wall-clock time, always timezone-aware UTC.

    Naive datetimes are banned throughout: every expiry comparison in the codebase would
    otherwise be one careless ``datetime.now()`` away from being wrong by hours.
    """

    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """A controllable clock for tests and for deterministic batch jobs."""

    def __init__(self, at: datetime) -> None:
        if at.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime.")
        self._at = at

    def now(self) -> datetime:
        return self._at

    def set(self, at: datetime) -> None:
        if at.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime.")
        self._at = at

    def advance(self, seconds: float) -> None:
        from datetime import timedelta

        self._at = self._at + timedelta(seconds=seconds)
