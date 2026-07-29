"""Event sink adapters.

Kafka is the production stream (ADR-0004): it decouples ingest spikes from analysis capacity
and gives replay for free. The file and memory sinks exist so the gateway is runnable and
testable without a broker — not as toys, but because a local developer and a CI job should be
able to exercise the real ingest path end to end.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from ..domain.errors import SinkUnavailableError
from ..domain.events import RuntimeEvent

DEFAULT_TOPIC = "runtime-events"


def _serialize(origin: StreamOrigin, event: RuntimeEvent) -> bytes:
    """The envelope the worker consumes.

    Every identity field is stamped here from the verified credential and never taken from
    the agent's payload — an agent must not be able to write into another tenant's stream, or
    attribute its findings to another application, by lying about who it is.
    """
    return json.dumps(
        {
            "organization_id": origin.organization_id,
            "agent_id": origin.agent_id,
            "environment_id": origin.environment_id,
            "event_id": event.event_id,
            "type": event.type.value,
            "occurred_at_ms": event.occurred_at_ms,
            "monotonic_nanos": event.monotonic_nanos,
            "trace_id": event.trace_id,
            "replayed": event.replayed,
            "payload": event.payload,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class MemoryEventSink:
    """Keeps everything in a list. Used by the test suite."""

    def __init__(self) -> None:
        self.published: list[tuple[str, RuntimeEvent]] = []
        self.fail_next = False

    async def publish(self, origin: StreamOrigin, events: list[RuntimeEvent]) -> None:
        if self.fail_next:
            self.fail_next = False
            raise SinkUnavailableError
        for event in events:
            self.published.append((origin.organization_id, event))

    async def close(self) -> None:
        return None


class FileEventSink:
    """Appends NDJSON to a file.

    The local-development default, and a genuinely useful air-gap mode: the file is the same
    shape Kafka would carry, so it can be shipped out of band and replayed.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def publish(self, origin: StreamOrigin, events: list[RuntimeEvent]) -> None:
        payload = b"\n".join(_serialize(origin, event) for event in events) + b"\n"
        try:
            async with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                # Written from a thread so a slow disk cannot stall the event loop and, with
                # it, every other tenant's ingest.
                await asyncio.to_thread(self._append, payload)
        except OSError as exc:
            raise SinkUnavailableError(str(exc)) from exc

    def _append(self, payload: bytes) -> None:
        with self._path.open("ab") as handle:
            handle.write(payload)

    async def close(self) -> None:
        return None


class KafkaEventSink:
    """Publishes to Kafka, partitioned by trace.

    ``aiokafka`` is an optional dependency: a deployment running the file sink should not have
    to install a broker client, so the import is deferred to construction.
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str = DEFAULT_TOPIC,
        *,
        acks: str | int = "all",
        linger_ms: int = 20,
    ) -> None:
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise SinkUnavailableError(
                "Kafka sink requires the 'kafka' extra: pip install aegis-gateway[kafka]"
            ) from exc

        self._topic = topic
        self._producer: Any = AIOKafkaProducer(
            bootstrap_servers=bootstrap_servers,
            # `acks=all` because losing a confirmed injection to a broker failover is not an
            # acceptable trade for a few milliseconds of latency.
            acks=acks,
            # A small linger batches the many small events a busy agent produces without
            # adding latency anyone can perceive.
            linger_ms=linger_ms,
            compression_type="gzip",
        )
        self._started = False

    async def start(self) -> None:
        if not self._started:
            await self._producer.start()
            self._started = True

    async def publish(self, origin: StreamOrigin, events: list[RuntimeEvent]) -> None:
        await self.start()
        try:
            for event in events:
                await self._producer.send_and_wait(
                    self._topic,
                    value=_serialize(origin, event),
                    key=event.partition_key.encode("utf-8"),
                )
        except Exception as exc:
            raise SinkUnavailableError(str(exc)) from exc

    async def close(self) -> None:
        if self._started:
            await self._producer.stop()
            self._started = False


def build_sink(destination: str) -> MemoryEventSink | FileEventSink | KafkaEventSink:
    """Choose a sink from a destination URI.

    ``kafka://host:9092/topic``, ``file:///var/log/aegis/events.ndjson`` or ``memory://``.
    """
    if destination.startswith("kafka://"):
        remainder = destination[len("kafka://") :]
        servers, _, topic = remainder.partition("/")
        return KafkaEventSink(servers, topic or DEFAULT_TOPIC)
    if destination.startswith("file:"):
        return FileEventSink(Path(destination[len("file:") :].lstrip("/")))
    return MemoryEventSink()
