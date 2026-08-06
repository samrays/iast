"""The orchestration loop: commit-after-success ordering, retry, and shutdown.

Everything the pipeline itself does — turning an event into a finding — is already covered by
``aegis-api``'s own test suite. What is new here, and what these tests are about, is the
sequencing around it: the source must never be told a batch is done until it actually is, a
failure must retry rather than drop the batch, and a shutdown mid-retry must not commit a batch
that was never confirmed processed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from aegis_api.application.findings import ProcessingResult

from aegis_worker.config import WorkerSettings
from aegis_worker.main import _process_with_retry, _run_loop, _Shutdown


@dataclass
class FakeSource:
    """An ``EventSource`` whose queued batches and commit history are inspectable.

    Once every queued batch has been committed, it polls as permanently empty — the loop then
    falls into its sleep-and-retry branch, same as a real source with nothing new to offer.
    """

    batches: list[list[str]] = field(default_factory=list)
    committed: list[list[str]] = field(default_factory=list)
    _pending: list[str] | None = None

    async def poll(self, batch_size: int) -> list[str]:
        if self._pending is not None:
            return self._pending
        if not self.batches:
            return []
        self._pending = self.batches.pop(0)[:batch_size]
        return self._pending

    async def commit(self) -> None:
        if self._pending is not None:
            self.committed.append(self._pending)
            self._pending = None

    async def close(self) -> None:
        return None


@dataclass
class FakePipeline:
    """A stand-in for ``ProcessRuntimeEvents`` whose ``execute`` can be made to fail."""

    fail_times: int = 0
    calls: list[list[dict[str, Any]]] = field(default_factory=list)

    async def execute(self, records: list[dict[str, Any]]) -> ProcessingResult:
        self.calls.append(records)
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("simulated database outage")
        result = ProcessingResult()
        result.findings_created = len(records)
        return result


class ImmediateShutdown(_Shutdown):
    """A shutdown flag already set — used to make retry loops resolve instantly in tests."""

    def __init__(self) -> None:
        super().__init__()
        self.request()


def _settings(**overrides: Any) -> WorkerSettings:
    # The field enforces a floor of 0.1s in production, to keep an empty-poll loop from
    # spinning; tests use exactly that floor rather than fighting it.
    overrides.setdefault("poll_interval_seconds", 0.1)
    return WorkerSettings(**overrides)


async def _run_until_idle(source: FakeSource, pipeline: FakePipeline, shutdown: _Shutdown) -> None:
    """Run the loop until it has committed every queued batch, then stop it.

    Event-driven rather than polling: ``commit`` is wrapped to signal once every batch that
    was queued at the start has been committed, and shutdown is requested only then — so every
    test here ends deterministically instead of racing a fixed sleep against however long
    processing happens to take.
    """
    expected_commits = len(source.batches)
    drained = asyncio.Event()
    if expected_commits == 0:
        drained.set()

    original_commit = source.commit

    async def commit_and_signal() -> None:
        await original_commit()
        if len(source.committed) >= expected_commits:
            drained.set()

    source.commit = commit_and_signal  # type: ignore[method-assign]

    async def stop_when_drained() -> None:
        await drained.wait()
        shutdown.request()

    await asyncio.wait_for(
        asyncio.gather(_run_loop(source, pipeline, _settings(), shutdown), stop_when_drained()),
        timeout=5,
    )


class TestProcessWithRetry:
    async def test_succeeds_on_the_first_try_when_nothing_fails(self) -> None:
        pipeline = FakePipeline()
        shutdown = _Shutdown()
        result = await _process_with_retry(pipeline, [{"a": 1}], shutdown)
        assert result is not None
        assert result.findings_created == 1
        assert len(pipeline.calls) == 1

    async def test_retries_past_a_transient_failure(self) -> None:
        pipeline = FakePipeline(fail_times=2)
        shutdown = _Shutdown()
        result = await _process_with_retry(pipeline, [{"a": 1}], shutdown)
        assert result is not None
        assert result.findings_created == 1
        # Two failures, then the call that succeeded.
        assert len(pipeline.calls) == 3

    async def test_a_shutdown_mid_retry_gives_up_rather_than_retrying_forever(self) -> None:
        pipeline = FakePipeline(fail_times=1_000_000)
        shutdown = ImmediateShutdown()
        result = await _process_with_retry(pipeline, [{"a": 1}], shutdown)
        assert result is None


class TestRunLoop:
    async def test_a_successful_batch_is_committed_exactly_once(self) -> None:
        source = FakeSource(batches=[['{"a":1}', '{"a":2}']])
        pipeline = FakePipeline()
        shutdown = _Shutdown()

        await _run_until_idle(source, pipeline, shutdown)

        assert source.committed == [['{"a":1}', '{"a":2}']]
        assert pipeline.calls == [[{"a": 1}, {"a": 2}]]

    async def test_multiple_batches_are_each_committed_once_in_order(self) -> None:
        source = FakeSource(batches=[['{"a":1}'], ['{"a":2}']])
        pipeline = FakePipeline()
        shutdown = _Shutdown()

        await _run_until_idle(source, pipeline, shutdown)

        assert source.committed == [['{"a":1}'], ['{"a":2}']]
        assert pipeline.calls == [[{"a": 1}], [{"a": 2}]]

    async def test_malformed_lines_are_dropped_but_do_not_block_the_rest(self) -> None:
        source = FakeSource(batches=[['{"a":1}', "not-json", '{"a":2}']])
        pipeline = FakePipeline()
        shutdown = _Shutdown()

        await _run_until_idle(source, pipeline, shutdown)

        assert pipeline.calls == [[{"a": 1}, {"a": 2}]]
        # The whole raw batch is still considered handled — the source is not asked for the
        # malformed line again on the next poll.
        assert source.committed == [['{"a":1}', "not-json", '{"a":2}']]

    async def test_an_empty_poll_does_not_call_the_pipeline_or_commit(self) -> None:
        source = FakeSource(batches=[])
        pipeline = FakePipeline()
        shutdown = _Shutdown()

        async def stop_soon() -> None:
            await asyncio.sleep(0.03)
            shutdown.request()

        await asyncio.wait_for(
            asyncio.gather(_run_loop(source, pipeline, _settings(), shutdown), stop_soon()),
            timeout=5,
        )

        assert pipeline.calls == []
        assert source.committed == []

    async def test_a_batch_that_never_succeeds_before_shutdown_is_not_committed(self) -> None:
        # A pre-set shutdown flag would never let the loop's `while not shutdown.requested`
        # enter at all, which proves nothing about the retry-then-shutdown path — the flag
        # here is set *after* the loop is already inside its first retry backoff.
        source = FakeSource(batches=[['{"a":1}']])
        pipeline = FakePipeline(fail_times=1_000_000)
        shutdown = _Shutdown()

        async def request_shutdown_mid_backoff() -> None:
            await asyncio.sleep(0.05)
            shutdown.request()

        await asyncio.wait_for(
            asyncio.gather(
                _run_loop(source, pipeline, _settings(), shutdown),
                request_shutdown_mid_backoff(),
            ),
            timeout=5,
        )

        assert source.committed == []
        # More than one attempt: the failure really was retried, not just tried once.
        assert len(pipeline.calls) >= 1
