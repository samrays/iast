"""Where the worker's events come from.

One contract, two adapters — the same shape as the gateway's own sinks, deliberately: a
``poll`` that returns whatever is new since the last commit, and a ``commit`` that the caller
invokes only after those records have been durably folded into findings. Nothing in this
module parses a record's contents; that stays in ``main.py``, next to the code that already
decides what a malformed one means (see ``operations.process_runtime_events``, which this
mirrors so the two do not quietly diverge on that decision).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import anyio.to_thread

from .cursor import FileCursor


class EventSource(Protocol):
    """A stream of raw NDJSON lines, with commit-after-processing semantics."""

    async def poll(self, batch_size: int) -> list[str]:
        """Up to ``batch_size`` new lines. Empty when there is nothing new right now.

        Calling this again before :meth:`commit` must return the *same* records, not the next
        ones — the caller has not finished with them yet, and silently advancing past
        unprocessed data would be exactly the kind of loss this worker exists to prevent.
        """
        ...

    async def commit(self) -> None:
        """Durably record that the most recent :meth:`poll` result has been processed."""
        ...

    async def close(self) -> None: ...


class FileTailSource:
    """Tails an NDJSON file the way the gateway's ``FileEventSink`` writes one.

    A local-development and air-gap-replay adapter, not a toy: it is the same file shape a
    Kafka capture can be exported to and back, so this and :class:`KafkaSource` read identical
    data (see ``FileEventSink`` in the gateway).
    """

    def __init__(self, path: Path, cursor: FileCursor) -> None:
        self._path = path
        self._cursor = cursor
        self._committed_offset = cursor.read()
        self._pending_offset: int | None = None
        self._pending_records: list[str] = []

    async def poll(self, batch_size: int) -> list[str]:
        if self._pending_offset is not None:
            # Not yet committed — hand back the same batch rather than reading further ahead.
            return self._pending_records
        records, new_offset = await anyio.to_thread.run_sync(self._read_batch, batch_size)
        if records:
            self._pending_offset = new_offset
            self._pending_records = records
        return records

    def _read_batch(self, batch_size: int) -> tuple[list[str], int]:
        if not self._path.is_file():
            return [], self._committed_offset
        records: list[str] = []
        offset = self._committed_offset
        with self._path.open("rb") as handle:
            handle.seek(offset)
            while len(records) < batch_size:
                line = handle.readline()
                if not line.endswith(b"\n"):
                    # Either EOF, or the writer is mid-append. Either way this line is not
                    # complete yet — leave the offset before it and pick it up next poll.
                    break
                offset = handle.tell()
                stripped = line.strip()
                if stripped:
                    records.append(stripped.decode("utf-8", errors="replace"))
        return records, offset

    async def commit(self) -> None:
        if self._pending_offset is None:
            return
        offset = self._pending_offset
        await anyio.to_thread.run_sync(self._cursor.advance, offset)
        self._committed_offset = offset
        self._pending_offset = None
        self._pending_records = []

    async def close(self) -> None:
        return None


class KafkaSource:
    """Consumes the production stream (ADR-0004), committing offsets manually.

    ``aiokafka`` is an optional dependency for the same reason it is on the gateway's producer
    side: a deployment running the file source for local development should not have to
    install a broker client.
    """

    def __init__(self, bootstrap_servers: str, topic: str, group_id: str) -> None:
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "Kafka source requires the 'kafka' extra: pip install -e .[kafka]"
            ) from exc

        self._consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            # Manual commit is the whole point: auto-commit would advance the offset on a
            # timer, independent of whether the batch it covers actually reached the database.
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        self._started = False
        self._pending = False

    async def _ensure_started(self) -> None:
        if not self._started:
            await self._consumer.start()
            self._started = True

    async def poll(self, batch_size: int) -> list[str]:
        if self._pending:
            # aiokafka has no "replay the last getmany" primitive; not committing already
            # leaves the broker's view of our position unmoved, so the only thing to avoid is
            # asking for *more* on top of an unprocessed batch.
            return []
        await self._ensure_started()
        result = await self._consumer.getmany(timeout_ms=2_000, max_records=batch_size)
        records = [
            message.value.decode("utf-8", errors="replace")
            for messages in result.values()
            for message in messages
        ]
        if records:
            self._pending = True
        return records

    async def commit(self) -> None:
        if not self._pending:
            return
        await self._consumer.commit()
        self._pending = False

    async def close(self) -> None:
        if self._started:
            await self._consumer.stop()
            self._started = False


def build_source(uri: str, *, consumer_group: str, cursor_override: str = "") -> EventSource:
    """Choose a source from a destination URI.

    ``kafka://host1:9092,host2:9092/topic`` or ``file:path/to/events.ndjson`` — the same shape
    the gateway's ``AEGIS_GATEWAY_EVENT_SINK`` accepts, parsed the same way (including its
    ``.lstrip("/")`` quirk: ``file:///abs/path`` loses its leading slash and becomes relative),
    so a URI copied from the gateway's config behaves identically here rather than needing its
    own translation.
    """
    if uri.startswith("kafka://"):
        remainder = uri[len("kafka://") :]
        servers, _, topic = remainder.partition("/")
        return KafkaSource(servers, topic or "runtime-events", consumer_group)
    if uri.startswith("file:"):
        path = Path(uri[len("file:") :].lstrip("/"))
        return FileTailSource(path, FileCursor.for_source(path, cursor_override))
    raise ValueError(f"unrecognised worker source: {uri!r}")
