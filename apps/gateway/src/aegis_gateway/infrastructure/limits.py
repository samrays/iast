"""In-process quota and deduplication.

Both are deliberately per-replica rather than shared through Redis. A cross-replica round trip
on every batch would put a network hop on the hottest path in the platform, and the guarantee
it buys is not worth it: quota is admission control, not billing, and a tenant briefly getting
N times its allowance across N replicas is harmless. Billing-grade accounting happens in the
worker, off the hot path, from the events themselves.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from ..domain.quota import TokenBucket


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now_ms(self) -> int:
        return int(time.time() * 1000)


class InMemoryQuotaLimiter:
    """Per-tenant token buckets held in this replica."""

    def __init__(
        self,
        *,
        events_per_second: float,
        burst_multiplier: float = 10.0,
        clock: SystemClock | None = None,
        max_tenants: int = 10_000,
    ) -> None:
        self._rate = events_per_second
        self._capacity = events_per_second * burst_multiplier
        self._clock = clock or SystemClock()
        self._buckets: OrderedDict[str, TokenBucket] = OrderedDict()
        self._max_tenants = max_tenants

    def _bucket(self, organization_id: str) -> TokenBucket:
        bucket = self._buckets.get(organization_id)
        if bucket is None:
            bucket = TokenBucket.create(self._capacity, self._rate, self._clock.monotonic())
            self._buckets[organization_id] = bucket
            # Bounded: a gateway facing many tenants must not accumulate a bucket per tenant
            # forever. Evicting the least recently used one only resets its allowance.
            if len(self._buckets) > self._max_tenants:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(organization_id)
        return bucket

    def check(self, organization_id: str, cost: float) -> bool:
        return self._bucket(organization_id).try_consume(cost, self._clock.monotonic())

    def remaining_fraction(self, organization_id: str) -> float:
        bucket = self._bucket(organization_id)
        # Refill before reading, so the fraction reflects now rather than the last write.
        bucket.try_consume(0.0, self._clock.monotonic())
        if bucket.capacity <= 0:
            return 0.0
        return max(0.0, min(1.0, bucket.tokens / bucket.capacity))

    def retry_after_seconds(self, organization_id: str, cost: float) -> int:
        return self._bucket(organization_id).retry_after_seconds(cost, self._clock.monotonic())


class LruDeduplicationCache:
    """Bounded set of recently seen event ids.

    The agent replays its spool after a reconnect, so without this every network blip inflates
    a tenant's findings. Bounded because unbounded memory in an ingest process is how a
    gateway dies under exactly the load it exists to absorb; an id evicted before its replay
    arrives simply costs one duplicate downstream, which the worker's deterministic finding
    identity absorbs (ADR-0009).
    """

    def __init__(self, capacity: int = 100_000) -> None:
        self._capacity = capacity
        self._seen: OrderedDict[str, None] = OrderedDict()

    def seen(self, event_id: str) -> bool:
        if event_id in self._seen:
            self._seen.move_to_end(event_id)
            return True
        return False

    def remember(self, event_id: str) -> None:
        self._seen[event_id] = None
        self._seen.move_to_end(event_id)
        while len(self._seen) > self._capacity:
            self._seen.popitem(last=False)

    def __len__(self) -> int:
        return len(self._seen)
