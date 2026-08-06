"""Worker entrypoint: fold the runtime event stream into findings, forever.

The loop is deliberately small — poll, parse, fold, commit, repeat — because the part that
actually decides what an event means already exists and is tested: this only owns pulling a
batch from wherever it lives and making sure the position only advances after the database has
durably accepted it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
from typing import Any

import structlog
from aegis_api.application.findings import ProcessingResult, ProcessRuntimeEvents
from aegis_api.config import Settings as ApiSettings
from aegis_api.container import Container, build_container
from aegis_api.observability import configure_logging

from .config import WorkerSettings
from .consumer import EventSource, build_source

logger = structlog.get_logger(__name__)

#: Ceiling on the backoff between retries of a failed batch. A worker that backs off forever
#: on a five-minute outage recovers five minutes late instead of instantly; one with no ceiling
#: at all can end up sleeping longer than the outage itself.
_MAX_BACKOFF_SECONDS = 30.0


class _Shutdown:
    """Cooperative shutdown flag, set from a signal handler and observed by the loop."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def request(self) -> None:
        self._event.set()

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    async def sleep(self, seconds: float) -> None:
        """Sleep, but wake immediately if a shutdown arrives mid-sleep.

        Without this a Ctrl+C during the poll-interval sleep, or mid-backoff after a failed
        batch, would sit there for up to :data:`_MAX_BACKOFF_SECONDS` before the process
        noticed — a worker that takes thirty seconds to respond to Ctrl+C trains an operator
        to send it twice, and the second one is SIGKILL.
        """
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._event.wait(), timeout=seconds)


def _install_signal_handlers(shutdown: _Shutdown) -> None:  # pragma: no cover
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Windows' asyncio event loop cannot register a SIGTERM handler. SIGINT (Ctrl+C)
        # still works; a process manager that needs to stop this worker on Windows without
        # it reaching this code has no graceful option to fall back to regardless.
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, shutdown.request)


async def _process_with_retry(
    pipeline: ProcessRuntimeEvents,
    records: list[dict[str, Any]],
    shutdown: _Shutdown,
) -> ProcessingResult | None:
    """Fold one batch, retrying with backoff on failure rather than giving up.

    Returns ``None`` only when a shutdown arrived while waiting to retry — the caller must not
    commit the source's position in that case, because the batch was never actually processed.
    """
    backoff = 1.0
    while True:
        try:
            return await pipeline.execute(records)
        except Exception:
            logger.exception(
                "batch_processing_failed", events=len(records), retry_in_seconds=backoff
            )
            await shutdown.sleep(backoff)
            if shutdown.requested:
                return None
            backoff = min(backoff * 2, _MAX_BACKOFF_SECONDS)


async def _run_loop(
    source: EventSource,
    pipeline: ProcessRuntimeEvents,
    settings: WorkerSettings,
    shutdown: _Shutdown,
) -> None:
    while not shutdown.requested:
        lines = await source.poll(settings.batch_size)
        if not lines:
            await shutdown.sleep(settings.poll_interval_seconds)
            continue

        records: list[dict[str, Any]] = []
        rejected_at_parse = 0
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # A malformed line must not wedge the stream forever behind a retry loop; it
                # is dropped, the same lenient handling the CLI replay path already uses.
                rejected_at_parse += 1

        if records:
            result = await _process_with_retry(pipeline, records, shutdown)
        else:
            result = ProcessingResult()
        if result is None:
            # Shutdown arrived mid-retry. The batch was never confirmed processed, so it must
            # not be committed — the next start picks up from the same, uncommitted position.
            return

        # Committed unconditionally once processing succeeds, whether or not it produced a
        # finding: "processed" and "produced output" are different questions, and only the
        # first is what makes advancing the position safe.
        await source.commit()
        logger.info(
            "batch_processed",
            events=len(lines),
            rejected_at_parse=rejected_at_parse,
            findings_created=result.findings_created,
            findings_updated=result.findings_updated,
            regressions=result.regressions,
            ignored=result.ignored,
            rejected=result.rejected,
        )


async def run_forever() -> None:  # pragma: no cover - pure composition, exercised by a live run
    worker_settings = WorkerSettings()
    api_settings = ApiSettings()
    configure_logging(api_settings)

    container: Container = build_container(api_settings)
    source = build_source(
        worker_settings.source,
        consumer_group=worker_settings.consumer_group,
        cursor_override=worker_settings.cursor_path,
    )
    pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

    shutdown = _Shutdown()
    _install_signal_handlers(shutdown)

    logger.info(
        "worker_started",
        source=worker_settings.source,
        batch_size=worker_settings.batch_size,
        poll_interval_seconds=worker_settings.poll_interval_seconds,
    )
    try:
        await _run_loop(source, pipeline, worker_settings, shutdown)
    finally:
        await source.close()
        await container.aclose()
        logger.info("worker_stopped")


def run() -> None:  # pragma: no cover - console-script entrypoint
    """Console-script entrypoint (``aegis-worker``)."""
    asyncio.run(run_forever())


if __name__ == "__main__":  # pragma: no cover
    run()
