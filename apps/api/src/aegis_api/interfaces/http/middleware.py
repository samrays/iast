"""HTTP middleware: request identity, structured access logs, security headers, metrics.

Written as **pure ASGI** middleware rather than Starlette's ``BaseHTTPMiddleware``. That
class wraps every request in an anyio task group and a pair of memory object streams, which
costs latency, breaks ``sys.settrace``-based tooling (coverage silently reports endpoint
bodies as unexecuted), and complicates exception propagation. Pure ASGI has none of those
problems and is what Starlette itself recommends for middleware that only needs to observe
or decorate the message stream.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from prometheus_client import Counter, Histogram
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUESTS = Counter(
    "aegis_http_requests_total",
    "HTTP requests handled.",
    labelnames=("method", "route", "status"),
)
LATENCY = Histogram(
    "aegis_http_request_duration_seconds",
    "HTTP request latency.",
    labelnames=("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


class RequestContextMiddleware:
    """Assigns a request id, binds logging context and emits a structured access log."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = headers.get("x-request-id") or uuid.uuid4().hex
        # ``scope["state"]`` is what Starlette's ``request.state`` reads from, so handlers
        # and exception handlers see the id without another lookup.
        scope.setdefault("state", {})["request_id"] = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=scope.get("method", ""),
            path=scope.get("path", ""),
            client_ip=client_ip_from_scope(scope),
        )

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                MutableHeaders(scope=message)["X-Request-Id"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - started
            _observe(scope, status_code, elapsed)
            structlog.get_logger("aegis.access").info(
                "http_request",
                status=status_code,
                duration_ms=round(elapsed * 1000, 2),
            )


class SecurityHeadersMiddleware:
    """Baseline response hardening.

    The API serves JSON to a separate origin, so the CSP is maximally restrictive: no
    scripts, no framing, no plugin content. The dashboard ships its own policy.
    """

    #: Applied to every response unless the handler already set the header.
    BASE_HEADERS: dict[str, str] = {  # noqa: RUF012 - a shared constant, intentionally
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        ),
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
        "Cross-Origin-Resource-Policy": "same-origin",
        # Authenticated API responses must never be cached by an intermediary.
        "Cache-Control": "no-store",
    }

    def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
        self.app = app
        self._headers = dict(self.BASE_HEADERS)
        if hsts:
            self._headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self._headers.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)


def _route_label(scope: Scope) -> str:
    """Use the route template, not the concrete path.

    Labelling metrics with raw paths would create one time series per resource id — a
    textbook cardinality explosion.
    """
    route: Any = scope.get("route")
    return str(getattr(route, "path", None) or scope.get("path", "unknown"))


def _observe(scope: Scope, status_code: int, elapsed: float) -> None:
    method = str(scope.get("method", "UNKNOWN"))
    route = _route_label(scope)
    REQUESTS.labels(method, route, str(status_code)).inc()
    LATENCY.labels(method, route).observe(elapsed)


def client_ip_from_scope(scope: Scope) -> str | None:
    """Best-effort client address.

    ``X-Forwarded-For`` is honoured because the service runs behind an ingress that sets
    it, and it is recorded for forensics only — never used for an authorization decision.
    """
    forwarded = Headers(scope=scope).get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else None


def _client_ip(request: Request) -> str | None:
    """Request-level convenience wrapper used by the dependency layer."""
    return client_ip_from_scope(request.scope)
