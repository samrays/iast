"""The ingest endpoint.

NDJSON rather than a JSON array, deliberately: an agent can stream lines as it drains its
buffer without holding the whole batch in memory, and a truncated upload leaves whole events
rather than an unparseable document.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Request, Response

from ...application.context import AgentPrincipal
from ...application.ingest import IngestResult
from ...domain.errors import AgentAuthenticationError
from ...infrastructure.auth import JwtAgentAuthenticator

router = APIRouter(prefix="/ingest/v1", tags=["ingest"])


def _principal(request: Request, authorization: str | None) -> AgentPrincipal:
    if not authorization:
        raise AgentAuthenticationError
    authenticator: JwtAgentAuthenticator = request.app.state.container.authenticator
    return authenticator.authenticate(authorization)


@router.post("/events", summary="Accept a batch of runtime events")
async def ingest_events(
    request: Request,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    principal = _principal(request, authorization)
    container = request.app.state.container

    body = await request.body()
    result: IngestResult = await container.ingest.execute(principal, body)

    # Credit-based backpressure: the agent throttles to this instead of discovering the limit
    # through a wall of 429s (ADR-0005).
    response.headers["X-Aegis-Credit"] = str(result.credit)

    container.metrics.record(principal.organization_id, result)

    return {
        "accepted": result.accepted,
        "duplicates": result.duplicates,
        "shed": result.shed,
        "rejected": result.rejected,
        "rejections": [rejection.as_dict() for rejection in result.rejections],
        "ack_cursor": result.ack_cursor,
        "credit": result.credit,
    }
