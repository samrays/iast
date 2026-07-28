"""Gateway application factory and operational endpoints."""

from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Environment, Settings, get_settings
from .container import build_container
from .interfaces.http.errors import register_exception_handlers
from .interfaces.http.ingest import router as ingest_router

DESCRIPTION = """
High-throughput ingest for Aegis IAST runtime agents.

Agents authenticate with a short-lived, audience-scoped credential and post NDJSON batches.
The gateway validates the wire schema, applies per-tenant quota, deduplicates replayed
events and publishes to the durable stream. It performs no database writes, which is what
lets it scale independently of the control plane.
"""


class RequestContextMiddleware:
    """Pure-ASGI request id and access log.

    Pure ASGI rather than `BaseHTTPMiddleware` for the same reason as the control plane: the
    latter wraps every request in a task group, which on an ingest path measured in tens of
    thousands of requests per second is a cost with no benefit.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id, path=scope.get("path", ""))

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-Id"] = request_id
            await send(message)

        await self.app(scope, receive, send_wrapper)


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        format="%(message)s", stream=sys.stdout, level=settings.log_level, force=True
    )
    processors: list[object] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    processors.append(
        structlog.dev.ConsoleRenderer(colors=True)
        if settings.environment is Environment.LOCAL
        else structlog.processors.JSONRenderer()
    )
    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, settings.log_level)),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    container = build_container(settings)
    app.state.container = container
    structlog.get_logger(__name__).info(
        "gateway_started",
        environment=settings.environment.value,
        sink=settings.event_sink.split("://")[0],
    )
    try:
        yield
    finally:
        await container.aclose()
        structlog.get_logger(__name__).info("gateway_stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="Aegis IAST — Ingest Gateway",
        version=settings.version,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if not settings.environment.is_production_like else None,
        redoc_url=None,
    )
    app.state.settings = settings

    register_exception_handlers(app)
    app.add_middleware(RequestContextMiddleware)
    app.include_router(ingest_router)

    @app.get("/healthz", tags=["operations"], summary="Liveness")
    async def healthz() -> dict[str, str]:
        # Touches nothing. A liveness probe that checks the broker would restart healthy
        # replicas during a Kafka blip and turn a degradation into an outage.
        return {"status": "ok", "service": settings.service_name, "version": settings.version}

    @app.get("/readyz", tags=["operations"], summary="Readiness")
    async def readyz(response: Response) -> dict[str, object]:
        checks: dict[str, str] = {"sink": "ok"}
        sink = getattr(app.state, "container", None)
        if sink is None:
            checks["sink"] = "not_initialised"
            response.status_code = 503
        ready = all(value == "ok" for value in checks.values())
        return {"status": "ready" if ready else "not_ready", "checks": checks}

    if settings.metrics_enabled:

        @app.get("/metrics", tags=["operations"], summary="Prometheus metrics")
        async def metrics() -> Response:
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
