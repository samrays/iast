"""Application factory and operational endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from .config import Settings, get_settings
from .container import build_container
from .interfaces.http.errors import register_exception_handlers
from .interfaces.http.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from .interfaces.http.routers import build_api_router
from .interfaces.http.schemas import HealthResponse, ReadinessResponse
from .observability import configure_logging

DESCRIPTION = """
Control plane for the Aegis Interactive Application Security Testing platform.

**Principals.** Three credential types are accepted, distinguished by JWT audience:
a user access token, an API key (`ak_<prefix>.<secret>`), and an agent token. An agent
token is rejected by every user-facing endpoint and vice versa.

**Errors.** Failures use RFC 9457 `application/problem+json`. A cross-tenant reference
returns `404`, never `403` — confirming existence would itself disclose information.

**Pagination.** Collections are cursor-paginated. Offset pagination is not offered.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    container = build_container(settings)
    app.state.container = container
    await _assert_least_privilege_database_role(container, settings)
    structlog.get_logger(__name__).info(
        "api_started",
        environment=settings.environment.value,
        version=settings.version,
    )
    try:
        yield
    finally:
        await container.aclose()
        structlog.get_logger(__name__).info("api_stopped")


async def _assert_least_privilege_database_role(container: object, settings: Settings) -> None:
    """Refuse to serve production traffic as a database superuser.

    PostgreSQL superusers **bypass row-level security entirely**, even on tables with
    ``FORCE ROW LEVEL SECURITY``. Connecting as one silently removes the second of the two
    tenant-isolation controls in ADR-0003 while every policy still appears to be in place —
    which is precisely the kind of failure nobody notices until it matters.
    """
    engine = container.engine  # type: ignore[attr-defined]
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            )
            is_superuser = bool(result.scalar())
    except Exception as exc:
        structlog.get_logger(__name__).warning("database_role_check_failed", error=str(exc))
        return

    if not is_superuser:
        return
    message = (
        "The database role is a superuser, so PostgreSQL row-level security is bypassed "
        "and tenant isolation rests on the repository layer alone. Create a dedicated "
        "NOSUPERUSER role for the application."
    )
    if settings.environment.is_production_like:
        raise RuntimeError(message)
    structlog.get_logger(__name__).warning("database_role_is_superuser", detail=message)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title=f"{settings.product_name} — Control Plane API",
        version=settings.version,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if not settings.environment.is_production_like else None,
        redoc_url=None,
        openapi_url="/openapi.json",
        swagger_ui_parameters={"persistAuthorization": True},
    )
    app.state.settings = settings

    register_exception_handlers(app)

    # Order matters: the outermost middleware runs first on the way in and last on the way
    # out, so the request id is assigned before anything else can log.
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.environment.is_production_like)
    app.add_middleware(RequestContextMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id", "Idempotency-Key"],
            expose_headers=["X-Request-Id", "RateLimit-Remaining", "Retry-After"],
            max_age=600,
        )

    app.include_router(build_api_router(settings.api_prefix))
    _register_operational_routes(app, settings)
    return app


def _register_operational_routes(app: FastAPI, settings: Settings) -> None:
    @app.get("/healthz", response_model=HealthResponse, tags=["operations"], summary="Liveness")
    async def healthz() -> HealthResponse:
        """Liveness only — deliberately touches no dependency.

        A liveness probe that checks the database restarts healthy pods during a database
        blip, turning a recoverable incident into an outage.
        """
        return HealthResponse(
            status="ok",
            service=settings.service_name,
            version=settings.version,
            environment=settings.environment.value,
        )

    @app.get(
        "/readyz",
        response_model=ReadinessResponse,
        tags=["operations"],
        summary="Readiness — checks dependencies",
    )
    async def readyz(response: Response) -> ReadinessResponse:
        checks: dict[str, str] = {}
        try:
            container = app.state.container
            async with container.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:
            checks["database"] = f"error: {type(exc).__name__}"

        ready = all(v == "ok" for v in checks.values())
        if not ready:
            response.status_code = 503
        return ReadinessResponse(status="ready" if ready else "not_ready", checks=checks)

    if settings.metrics_enabled:

        @app.get("/metrics", tags=["operations"], summary="Prometheus metrics")
        async def metrics() -> Response:
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/version", tags=["operations"], summary="Build information")
    async def version() -> dict[str, str]:
        return {"service": settings.service_name, "version": settings.version}


app = create_app()
