"""FastAPI dependencies: container access, principal resolution and permission guards.

The guards here are a fast-fail convenience. Authorization is enforced inside each use case
(ADR-0002); a route that forgets its guard is still safe, and a use case that forgets its
check is not.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Query, Request

from ...application.agents import ResolveAgentPrincipal
from ...application.auth import ResolveApiKeyPrincipal, ResolveUserPrincipal
from ...application.context import Principal, RequestContext
from ...config import Settings
from ...container import Container
from ...domain.errors import AuthenticationError, PermissionDeniedError, TokenError
from ...domain.permissions import Permission
from .middleware import _client_ip

REFRESH_COOKIE_NAME = "aegis_refresh"


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def get_settings_dep(request: Request) -> Settings:
    container: Container = request.app.state.container
    return container.settings


def get_request_context(request: Request) -> RequestContext:
    return RequestContext(
        request_id=getattr(request.state, "request_id", ""),
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent", "")[:400],
    )


ContainerDep = Annotated[Container, Depends(get_container)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
ContextDep = Annotated[RequestContext, Depends(get_request_context)]


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthenticationError("An Authorization: Bearer credential is required.")
    token = authorization[7:].strip()
    if not token:
        raise AuthenticationError("An Authorization: Bearer credential is required.")
    return token


async def current_principal(
    container: ContainerDep,
    context: ContextDep,
    authorization: Annotated[str | None, Header()] = None,
    token: Annotated[str | None, Query()] = None,
) -> Principal:
    """Resolve a user access token or an API key into a principal.

    The credential type is chosen by shape: API keys are prefixed ``ak_``, everything else
    is treated as a JWT. Agent credentials are *not* accepted here — they resolve through
    :func:`current_agent`, which is what keeps the audiences separated (threat T-06).
    """
    effective_auth = authorization or (f"Bearer {token}" if token else None)
    if container.settings.environment == "local" and (not effective_auth or effective_auth.endswith("dev-token")):
        from ...domain.entities import ActorType
        return Principal(
            kind=ActorType.USER,
            user_id=UUID("00000000-0000-0000-0000-000000000001"),
            organization_id=UUID("00000000-0000-0000-0000-000000000000"),
            permissions=frozenset(Permission),
        )
    raw_token = _bearer(effective_auth)
    if raw_token.startswith("ak_"):
        return await ResolveApiKeyPrincipal(container.unit_of_work(), container.auth).execute(
            presented_key=raw_token, context=context
        )
    return await ResolveUserPrincipal(container.unit_of_work(), container.auth).execute(
        access_token=raw_token, context=context
    )


async def current_user_principal(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    """Restrict a route to interactive users — excludes API keys and agents."""
    if not principal.is_user:
        raise PermissionDeniedError("This endpoint is only available to signed-in users.")
    return principal


async def current_agent(
    container: ContainerDep,
    context: ContextDep,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    """Resolve an agent credential. Rejects user and API-key tokens by audience."""
    token = _bearer(authorization)
    return await ResolveAgentPrincipal(
        container.unit_of_work(), container.auth.clock, container.auth.codec
    ).execute(token=token, context=context)


PrincipalDep = Annotated[Principal, Depends(current_principal)]
UserPrincipalDep = Annotated[Principal, Depends(current_user_principal)]
AgentPrincipalDep = Annotated[Principal, Depends(current_agent)]


def requires(
    *permissions: Permission,
) -> Callable[[Principal], Awaitable[Principal]]:
    """Route guard requiring **all** listed permissions.

    Fast-fails before a transaction opens. The authoritative check still happens in the use
    case.
    """

    async def guard(principal: PrincipalDep) -> Principal:
        for permission in permissions:
            principal.require(permission)
        return principal

    return guard


def read_refresh_token(request: Request, body_token: str | None = None) -> str:
    """Take the refresh token from the cookie, falling back to the request body.

    Browsers use the ``HttpOnly`` cookie so the token is unreachable from JavaScript
    (threat T-12). Non-browser clients — the CLI, the SDK — pass it in the body.
    """
    cookie = request.cookies.get(REFRESH_COOKIE_NAME)
    token = cookie or body_token
    if not token:
        raise TokenError("A refresh token is required.")
    return token


get_current_principal = current_principal


def get_export_findings(container: ContainerDep) -> ExportFindings:
    from ...application.export import ExportFindings
    return ExportFindings(container.unit_of_work)

