"""Domain error → HTTP mapping, in exactly one place.

Responses follow RFC 9457 ``application/problem+json``. The mapping lives here and nowhere
else: a router that invents its own ``HTTPException`` for a domain condition is a bug,
because the status code for a rule then depends on which route you happened to call.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ...domain.errors import (
    AccountDisabledError,
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    DomainError,
    FeatureNotLicensedError,
    InvalidMfaCodeError,
    InvalidStateError,
    LicenseLimitExceededError,
    NotFoundError,
    PermissionDeniedError,
    PrivilegeEscalationError,
    RateLimitExceededError,
    TokenError,
    TokenReuseError,
    ValidationError,
    WeakPasswordError,
)

PROBLEM_MEDIA_TYPE = "application/problem+json"
_DOC_BASE = "https://docs.aegis.dev/errors"

#: Starlette renamed this constant to match RFC 9110's "Unprocessable Content". Resolve it
#: at import time so the code works on both spellings.
HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)

#: Domain error → HTTP status. Anything not listed is a 400; anything not a DomainError is
#: a 500 with no detail leaked.
_STATUS_MAP: dict[type[DomainError], int] = {
    ValidationError: HTTP_422,
    WeakPasswordError: HTTP_422,
    NotFoundError: status.HTTP_404_NOT_FOUND,
    ConflictError: status.HTTP_409_CONFLICT,
    InvalidStateError: status.HTTP_409_CONFLICT,
    AuthenticationError: status.HTTP_401_UNAUTHORIZED,
    TokenError: status.HTTP_401_UNAUTHORIZED,
    TokenReuseError: status.HTTP_401_UNAUTHORIZED,
    InvalidMfaCodeError: status.HTTP_401_UNAUTHORIZED,
    AccountDisabledError: status.HTTP_403_FORBIDDEN,
    AccountLockedError: status.HTTP_423_LOCKED,
    PermissionDeniedError: status.HTTP_403_FORBIDDEN,
    PrivilegeEscalationError: status.HTTP_403_FORBIDDEN,
    LicenseLimitExceededError: status.HTTP_402_PAYMENT_REQUIRED,
    FeatureNotLicensedError: status.HTTP_402_PAYMENT_REQUIRED,
    RateLimitExceededError: status.HTTP_429_TOO_MANY_REQUESTS,
}


def status_for(error: DomainError) -> int:
    for error_type in type(error).__mro__:
        if error_type in _STATUS_MAP:
            return _STATUS_MAP[error_type]
    return status.HTTP_400_BAD_REQUEST


def problem(
    *,
    status_code: int,
    title: str,
    code: str,
    detail: str,
    request: Request,
    errors: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"{_DOC_BASE}/{code.replace('_', '-')}",
        "title": title,
        "status": status_code,
        "detail": detail,
        "instance": request.url.path,
        "code": code,
        "request_id": getattr(request.state, "request_id", ""),
    }
    if errors:
        body["errors"] = errors
    if extra:
        body.update(extra)
    return JSONResponse(
        status_code=status_code, content=body, media_type=PROBLEM_MEDIA_TYPE, headers=headers
    )


def _titleize(code: str) -> str:
    return code.replace("_", " ").capitalize()


async def domain_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, DomainError)
    status_code = status_for(exc)
    headers: dict[str, str] = {}
    extra: dict[str, Any] = {}
    errors: list[dict[str, Any]] | None = None

    if isinstance(exc, AccountLockedError | RateLimitExceededError):
        headers["Retry-After"] = str(exc.retry_after_seconds)
    if isinstance(exc, AuthenticationError | TokenError):
        headers["WWW-Authenticate"] = 'Bearer realm="aegis"'
    if isinstance(exc, WeakPasswordError):
        errors = [
            {"field": "password", "code": "policy", "message": f"Password {f}."}
            for f in exc.failures
        ]
    elif isinstance(exc, ValidationError) and exc.field:
        errors = [{"field": exc.field, "code": exc.code, "message": exc.message}]
        # ``organizations`` is surfaced so the client can prompt for a tenant choice on
        # sign-in rather than leaving the user stuck.
        if "organizations" in exc.context:
            extra["organizations"] = exc.context["organizations"]
    if isinstance(exc, PrivilegeEscalationError):
        extra["missing_permissions"] = exc.permissions

    return problem(
        status_code=status_code,
        title=_titleize(exc.code),
        code=exc.code,
        detail=exc.message,
        request=request,
        errors=errors,
        headers=headers or None,
        extra=extra or None,
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    errors = [
        {
            "field": ".".join(str(part) for part in err.get("loc", ())[1:]) or "body",
            "code": str(err.get("type", "invalid")),
            "message": str(err.get("msg", "Invalid value")),
        }
        for err in exc.errors()
    ]
    return problem(
        status_code=HTTP_422,
        title="Validation failed",
        code="validation_error",
        detail="The request body or parameters did not pass validation.",
        request=request,
        errors=errors,
    )


async def http_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    return problem(
        status_code=exc.status_code,
        title=_titleize(str(exc.detail)) if isinstance(exc.detail, str) else "Error",
        code="http_error",
        detail=str(exc.detail),
        request=request,
        headers=dict(exc.headers or {}) or None,
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last resort.

    The exception detail is logged, never returned: an internal message can disclose
    schema, file paths or credentials. The request id is the support handle.
    """
    import structlog

    structlog.get_logger(__name__).exception(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        request_id=getattr(request.state, "request_id", ""),
    )
    return problem(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Internal server error",
        code="internal_error",
        detail="An unexpected error occurred. Quote the request id when contacting support.",
        request=request,
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DomainError, domain_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
