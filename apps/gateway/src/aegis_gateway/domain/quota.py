"""Per-tenant ingest quota and backpressure policy.

Both are pure and exhaustively testable, which matters because they decide what the platform
throws away under load — and getting that wrong means either dropping a confirmed injection
or letting one noisy tenant starve every other.
"""

from __future__ import annotations

from dataclasses import dataclass

from .events import EventType


@dataclass(slots=True)
class TokenBucket:
    """Classic token bucket, refilled continuously rather than on a fixed window boundary.

    A fixed window lets a tenant spend its entire allowance in the last millisecond of one
    window and again in the first millisecond of the next — twice the intended rate, right at
    the boundary. Continuous refill has no such edge.
    """

    capacity: float
    refill_per_second: float
    tokens: float
    updated_at: float

    @classmethod
    def create(cls, capacity: float, refill_per_second: float, now: float) -> TokenBucket:
        return cls(
            capacity=capacity,
            refill_per_second=refill_per_second,
            tokens=capacity,
            updated_at=now,
        )

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated_at)
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.updated_at = now

    def try_consume(self, amount: float, now: float) -> bool:
        """Take ``amount`` tokens if available. Never blocks and never goes negative."""
        self._refill(now)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

    def retry_after_seconds(self, amount: float, now: float) -> int:
        """How long until ``amount`` tokens exist, rounded up to a whole second."""
        self._refill(now)
        if self.tokens >= amount:
            return 0
        if self.refill_per_second <= 0:
            # A zero-rate bucket never refills; tell the caller to back off substantially
            # rather than hammering us every second.
            return 3600
        deficit = amount - self.tokens
        return max(1, int(deficit / self.refill_per_second) + 1)


@dataclass(frozen=True, slots=True)
class SheddingPolicy:
    """Decides what to discard when the tenant is over quota.

    The rule is absolute and deliberately not configurable: **security signal is never shed**.
    A gateway that drops a confirmed injection to protect its own throughput has inverted its
    purpose. Inventory, dependency and coverage telemetry are regenerated on the next
    heartbeat, so losing them costs nothing but freshness.
    """

    #: Fraction of quota below which even low-value events are still accepted.
    comfortable_fraction: float = 0.5

    def should_accept(self, event_type: EventType, remaining_fraction: float) -> bool:
        if event_type.is_security_signal:
            return True
        return remaining_fraction >= (1.0 - self.comfortable_fraction)

    def cost(self, event_type: EventType) -> float:
        """Quota cost of one event.

        Security signal is charged less than telemetry. Under sustained pressure that biases
        what survives toward what matters, without needing a separate priority queue.
        """
        return 0.5 if event_type.is_security_signal else 1.0
