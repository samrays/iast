"""Worker configuration.

Deliberately small. The worker reuses ``aegis_api.config.Settings`` for everything database-
related — the two processes must agree on where the data lives, and a second copy of that
parsing logic is a second place for it to drift. This module holds only what is specific to
being a worker: where the event stream is, how fast to poll it, how big a batch to fold at
once.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    """Runtime configuration, populated from ``AEGIS_WORKER_*`` environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_WORKER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    #: ``file:<path>`` or ``kafka://host1:9092,host2:9092/topic`` — the same URI shape the
    #: gateway's ``AEGIS_GATEWAY_EVENT_SINK`` already uses, deliberately, so pointing a worker
    #: at a gateway is copying one value rather than translating it.
    source: str = "file:.local-data/aegis-events.ndjson"

    #: Kafka only. A named group lets a second worker process take over automatically if this
    #: one dies, rather than every restart re-reading from the beginning of the topic.
    consumer_group: str = "aegis-worker"

    #: Events folded into one database transaction. Matches the CLI's historical default so a
    #: capture that was memory-safe as a one-shot replay stays memory-safe running forever.
    batch_size: Annotated[int, Field(ge=1, le=10_000)] = 500

    #: How long to sleep after finding nothing new, file mode only. Kafka's consumer already
    #: blocks efficiently on ``getmany``; a file has no equivalent to wait on, so this is a
    #: plain poll interval.
    poll_interval_seconds: Annotated[float, Field(ge=0.1, le=60)] = 2.0

    #: Where the file-mode cursor is kept. Empty means "next to the source file", which is the
    #: right default for local development and wrong for a read-only mounted capture — hence
    #: the override.
    cursor_path: str = ""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    service_name: str = "aegis-worker"
