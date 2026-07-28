"""Domain error → HTTP mapping for the gateway.

RFC 9457 problem documents, as in the control plane. The status codes matter more here than
usual, because an agent behaves differently on each: 4xx means "this batch is bad, drop it",
5xx and 429 mean "keep it and retry".
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from ...domain.errors import (
    AgentAuthenticationError,
    AgentDisabledError,
    BatchTooLargeError,
    GatewayError,
    InvalidEventError,
    QuotaExceededError,
    SinkUnavailableError,
)

PROBLEM_MEDIA_TYPE = "application/problem+json"
_DOC_BASE = "https://docs.aegis.dev/errors"

HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)
# Starlette renamed this to match RFC 9110's "Content Too Large"; resolve whichever exists.
HTTP_413 = getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413)

_STATUS_MAP: dict[type[GatewayError], int] = {
    AgentAuthenticationError: status.HTTP_401_UNAUTHORIZED,
    AgentDisabledError: status.HTTP_403_FORBIDDEN,
    InvalidEventError: HTTP_422,
    BatchTooLargeError: HTTP_413,
    QuotaExceededError: status.HTTP_429_TOO_MANY_REQUESTS,
    # 503, not 500: the batch is fine and the agent should keep it spooled and try again.
    SinkUnavailableError: status.HTTP_503_SERVICE_UNAVAILABLE,
}


def status_for(error: GatewayError) -> int:
    for error_type in type(error).__mro__:
        if error_type in _STATUS_MAP:
            return _STATUS_MAP[error_type]
    return status.HTTP_400_BAD_REQUEST


async def gateway_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, GatewayError)
    status_code = status_for(exc)
    headers: dict[str, str] = {}

    if isinstance(exc, QuotaExceededError):
        headers["Retry-After"] = str(exc.retry_after_seconds)
    if isinstance(exc, SinkUnavailableError):
        # Tell the agent to back off briefly rather than hot-looping against a broker that is
        # already struggling.
        headers["Retry-After"] = "5"
    if isinstance(exc, AgentAuthenticationError):
        headers["WWW-Authenticate"] = 'Bearer realm="aegis-ingest"'

    body: dict[str, Any] = {
        "type": f"{_DOC_BASE}/{exc.code.replace('_', '-')}",
        "title": exc.code.replace("_", " ").capitalize(),
        "status": status_code,
        "detail": exc.message,
        "instance": request.url.path,
        "code": exc.code,
        "request_id": getattr(request.state, "request_id", ""),
    }
    return JSONResponse(
        status_code=status_code,
        content=body,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers or None,
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    import structlog

    structlog.get_logger(__name__).exception(
        "unhandled_exception", path=request.url.path, method=request.method
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "type": f"{_DOC_BASE}/internal-error",
            "title": "Internal server error",
            "status": 500,
            "detail": "An unexpected error occurred.",
            "instance": request.url.path,
            "code": "internal_error",
            "request_id": getattr(request.state, "request_id", ""),
        },
        media_type=PROBLEM_MEDIA_TYPE,
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(GatewayError, gateway_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
