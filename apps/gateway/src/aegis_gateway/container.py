"""Composition root for the gateway."""

from __future__ import annotations

from dataclasses import dataclass, field

from prometheus_client import Counter, Histogram

from .application.ingest import IngestEvents, IngestResult
from .config import Settings
from .domain.quota import SheddingPolicy
from .infrastructure.auth import JwtAgentAuthenticator
from .infrastructure.limits import InMemoryQuotaLimiter, LruDeduplicationCache
from .infrastructure.sinks import build_sink

EVENTS = Counter(
    "aegis_gateway_events_total",
    "Runtime events by disposition.",
    labelnames=("disposition",),
)
BATCH_SIZE = Histogram(
    "aegis_gateway_batch_events",
    "Events per accepted batch.",
    buckets=(1, 8, 32, 128, 512, 2048),
)


class Metrics:
    """Records ingest outcomes.

    Labelled by disposition only, never by tenant: one time series per organization would be
    a cardinality explosion in Prometheus the first time the platform had real customers.
    Per-tenant volume is answered from the event stream itself.
    """

    def record(self, organization_id: str, result: IngestResult) -> None:
        if result.accepted:
            EVENTS.labels("accepted").inc(result.accepted)
            BATCH_SIZE.observe(result.accepted)
        if result.duplicates:
            EVENTS.labels("duplicate").inc(result.duplicates)
        if result.shed:
            EVENTS.labels("shed").inc(result.shed)
        if result.rejected:
            EVENTS.labels("rejected").inc(result.rejected)


@dataclass
class Container:
    settings: Settings
    authenticator: JwtAgentAuthenticator
    ingest: IngestEvents
    sink: object
    metrics: Metrics = field(default_factory=Metrics)

    async def aclose(self) -> None:
        close = getattr(self.sink, "close", None)
        if close is not None:
            await close()


def build_container(settings: Settings) -> Container:
    authenticator = JwtAgentAuthenticator(
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        issuer=settings.jwt_issuer,
        public_key=settings.jwt_public_key,
    )
    sink = build_sink(settings.event_sink)
    quota = InMemoryQuotaLimiter(
        events_per_second=settings.quota_events_per_second,
        burst_multiplier=settings.quota_burst_multiplier,
    )
    dedup = LruDeduplicationCache(capacity=settings.dedup_cache_size)

    ingest = IngestEvents(
        sink=sink,
        quota=quota,
        dedup=dedup,
        max_batch_bytes=settings.max_batch_bytes,
        max_batch_events=settings.max_batch_events,
        shedding=SheddingPolicy(),
        reject_batch_on_invalid=settings.reject_batch_on_invalid,
    )
    return Container(settings=settings, authenticator=authenticator, ingest=ingest, sink=sink)
