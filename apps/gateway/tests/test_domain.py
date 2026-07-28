"""Pure domain tests: quota arithmetic, shedding policy, dedup and sinks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_gateway.domain.errors import InvalidEventError, SinkUnavailableError
from aegis_gateway.domain.events import EventType, parse_event
from aegis_gateway.domain.quota import SheddingPolicy, TokenBucket
from aegis_gateway.infrastructure.limits import InMemoryQuotaLimiter, LruDeduplicationCache
from aegis_gateway.infrastructure.sinks import FileEventSink, MemoryEventSink, build_sink


class TestTokenBucket:
    def test_starts_full_and_spends_down(self) -> None:
        bucket = TokenBucket.create(capacity=10, refill_per_second=1, now=0.0)
        assert all(bucket.try_consume(1, 0.0) for _ in range(10))
        assert not bucket.try_consume(1, 0.0)

    def test_refills_continuously_rather_than_on_a_window_boundary(self) -> None:
        # A fixed window lets a tenant spend its whole allowance at the end of one window and
        # again at the start of the next — twice the intended rate, right at the boundary.
        bucket = TokenBucket.create(capacity=10, refill_per_second=2, now=0.0)
        for _ in range(10):
            bucket.try_consume(1, 0.0)

        assert not bucket.try_consume(1, 0.0)
        assert bucket.try_consume(1, 0.5)  # 0.5s at 2/s = 1 token
        assert not bucket.try_consume(1, 0.5)

    def test_never_exceeds_capacity_however_long_it_idles(self) -> None:
        bucket = TokenBucket.create(capacity=10, refill_per_second=100, now=0.0)
        bucket.try_consume(10, 0.0)
        bucket.try_consume(0, 10_000.0)
        assert bucket.tokens == 10

    def test_reports_when_capacity_returns(self) -> None:
        bucket = TokenBucket.create(capacity=10, refill_per_second=2, now=0.0)
        bucket.try_consume(10, 0.0)
        assert bucket.retry_after_seconds(4, 0.0) == 3
        assert bucket.retry_after_seconds(0, 0.0) == 0

    def test_a_zero_rate_bucket_backs_the_caller_right_off(self) -> None:
        bucket = TokenBucket.create(capacity=1, refill_per_second=0, now=0.0)
        bucket.try_consume(1, 0.0)
        # Telling a client to retry in one second against a bucket that never refills is just
        # an invitation to hammer us.
        assert bucket.retry_after_seconds(1, 0.0) == 3600


class TestSheddingPolicy:
    @pytest.mark.parametrize("event_type", [EventType.TAINT_HIT, EventType.ATTACK])
    def test_never_sheds_security_signal(self, event_type: EventType) -> None:
        policy = SheddingPolicy()
        # Absolute, at any remaining fraction. A gateway that drops a confirmed injection to
        # protect its own throughput has inverted its purpose.
        assert policy.should_accept(event_type, remaining_fraction=0.0)

    @pytest.mark.parametrize(
        "event_type",
        [EventType.ROUTE, EventType.DEPENDENCY, EventType.CONFIG, EventType.COVERAGE_GAP],
    )
    def test_sheds_telemetry_under_pressure(self, event_type: EventType) -> None:
        policy = SheddingPolicy()
        assert policy.should_accept(event_type, remaining_fraction=0.9)
        assert not policy.should_accept(event_type, remaining_fraction=0.1)

    def test_charges_security_signal_less(self) -> None:
        policy = SheddingPolicy()
        # Biases what survives sustained pressure toward what matters, without needing a
        # separate priority queue.
        assert policy.cost(EventType.TAINT_HIT) < policy.cost(EventType.ROUTE)


class TestQuotaLimiter:
    def test_isolates_tenants_from_each_other(self) -> None:
        limiter = InMemoryQuotaLimiter(events_per_second=1, burst_multiplier=2)
        for _ in range(2):
            limiter.check("noisy-tenant", 1)

        assert not limiter.check("noisy-tenant", 1)
        # One tenant exhausting its allowance must not affect anyone else.
        assert limiter.check("quiet-tenant", 1)

    def test_bounds_the_number_of_tracked_tenants(self) -> None:
        limiter = InMemoryQuotaLimiter(events_per_second=10, max_tenants=3)
        for index in range(10):
            limiter.check(f"tenant-{index}", 1)
        # Unbounded state in an ingest process is how a gateway dies under the load it exists
        # to absorb.
        assert len(limiter._buckets) <= 3

    def test_remaining_fraction_tracks_consumption(self) -> None:
        limiter = InMemoryQuotaLimiter(events_per_second=10, burst_multiplier=1)
        assert limiter.remaining_fraction("t") == pytest.approx(1.0)
        limiter.check("t", 5)
        assert limiter.remaining_fraction("t") < 1.0


class TestDeduplicationCache:
    def test_remembers_and_recognises(self) -> None:
        cache = LruDeduplicationCache(capacity=10)
        assert not cache.seen("evt-1")
        cache.remember("evt-1")
        assert cache.seen("evt-1")

    def test_evicts_least_recently_used(self) -> None:
        cache = LruDeduplicationCache(capacity=3)
        for index in range(5):
            cache.remember(f"evt-{index}")

        assert len(cache) == 3
        assert not cache.seen("evt-0")
        assert cache.seen("evt-4")

    def test_lookup_refreshes_recency(self) -> None:
        cache = LruDeduplicationCache(capacity=3)
        for index in range(3):
            cache.remember(f"evt-{index}")

        cache.seen("evt-0")  # touch the oldest
        cache.remember("evt-3")

        assert cache.seen("evt-0")
        assert not cache.seen("evt-1")


class TestEventParsing:
    def test_partition_key_falls_back_to_the_event_id(self) -> None:
        event = parse_event(
            {
                "event_id": "evt-1",
                "type": "EVENT_TYPE_ROUTE",
                "occurred_at_ms": 1,
                "route": {"method": "GET", "path_template": "/x", "authenticated": False},
            },
            1,
        )
        # Without the fallback, every traceless event would hot-spot partition zero.
        assert event.partition_key == "evt-1"

    def test_rejects_a_non_object(self) -> None:
        with pytest.raises(InvalidEventError):
            parse_event(["not", "an", "object"], 1)

    def test_rejects_a_blank_event_id(self) -> None:
        with pytest.raises(InvalidEventError, match="blank"):
            parse_event(
                {"event_id": "   ", "type": "EVENT_TYPE_ROUTE", "occurred_at_ms": 1, "route": {}}, 1
            )

    def test_rejects_a_non_positive_timestamp(self) -> None:
        with pytest.raises(InvalidEventError, match="positive"):
            parse_event(
                {"event_id": "e", "type": "EVENT_TYPE_ROUTE", "occurred_at_ms": 0, "route": {}}, 1
            )

    def test_carries_the_line_number_for_the_agent_author(self) -> None:
        with pytest.raises(InvalidEventError) as excinfo:
            parse_event({"event_id": "e"}, 42)
        assert excinfo.value.line == 42


class TestSinks:
    async def test_memory_sink_records_the_tenant(self) -> None:
        sink = MemoryEventSink()
        event = parse_event(
            {
                "event_id": "evt-1",
                "type": "EVENT_TYPE_ROUTE",
                "occurred_at_ms": 1,
                "route": {"method": "GET", "path_template": "/x", "authenticated": False},
            },
            1,
        )
        await sink.publish("org-1", [event])
        assert sink.published == [("org-1", event)]

    async def test_file_sink_writes_the_stream_shape(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "events.ndjson"
        sink = FileEventSink(target)
        event = parse_event(
            {
                "event_id": "evt-1",
                "type": "EVENT_TYPE_ROUTE",
                "occurred_at_ms": 1,
                "trace_id": "t-1",
                "route": {"method": "GET", "path_template": "/x", "authenticated": False},
            },
            1,
        )
        await sink.publish("org-1", [event])
        await sink.close()

        written = json.loads(target.read_text(encoding="utf-8").strip())
        # The tenant is stamped from the verified credential, never from the agent payload.
        assert written["organization_id"] == "org-1"
        assert written["type"] == "EVENT_TYPE_ROUTE"

    async def test_file_sink_surfaces_io_failure_as_retryable(self, tmp_path: Path) -> None:
        # A directory where a file should be: the write cannot succeed.
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        sink = FileEventSink(blocked)
        event = parse_event(
            {
                "event_id": "evt-1",
                "type": "EVENT_TYPE_ROUTE",
                "occurred_at_ms": 1,
                "route": {"method": "GET", "path_template": "/x", "authenticated": False},
            },
            1,
        )
        with pytest.raises(SinkUnavailableError):
            await sink.publish("org-1", [event])

    def test_build_sink_chooses_by_scheme(self, tmp_path: Path) -> None:
        assert isinstance(build_sink("memory://"), MemoryEventSink)
        assert isinstance(build_sink(f"file:{tmp_path / 'x.ndjson'}"), FileEventSink)
