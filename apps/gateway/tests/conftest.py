"""Gateway test fixtures.

No database and no broker: the gateway is stateless by design, so its tests are fast and
hermetic. The one thing that must be real is the credential — tokens are minted with the same
codec the control plane uses, so a signature or audience change in Phase 2 breaks these tests
rather than production.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
import pytest_asyncio

from aegis_gateway.config import Environment, Settings, get_settings
from aegis_gateway.infrastructure.sinks import MemoryEventSink
from aegis_gateway.main import create_app

JWT_SECRET = "gateway-test-secret-that-is-long-enough-to-be-plausible"
ISSUER = "https://api.aegis.test"
ORGANIZATION_ID = "018f2b00-0000-7000-8000-000000000001"
AGENT_ID = "018f2b00-0000-7000-8000-0000000000a1"


@pytest.fixture(scope="session")
def settings() -> Settings:
    get_settings.cache_clear()
    return Settings(
        environment=Environment.TEST,
        jwt_secret=JWT_SECRET,
        jwt_issuer=ISSUER,
        event_sink="memory://",
        quota_events_per_second=1_000.0,
        metrics_enabled=False,
    )


def make_agent_token(
    *,
    organization_id: str = ORGANIZATION_ID,
    agent_id: str = AGENT_ID,
    audience: str = "aegis:agent",
    purpose: str = "agent",
    issuer: str = ISSUER,
    secret: str = JWT_SECRET,
    expires_in: int = 3600,
) -> str:
    """Mint a token exactly as `JwtAccessTokenCodec.issue_challenge` does."""
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": agent_id,
        "org": organization_id,
        "purpose": purpose,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    return jwt.encode(claims, secret, algorithm="HS256")


@pytest.fixture
def agent_token() -> str:
    return make_agent_token()


@pytest.fixture
def auth_headers(agent_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {agent_token}", "Content-Type": "application/x-ndjson"}


@pytest_asyncio.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
            http.app = app  # type: ignore[attr-defined]
            yield http


@pytest.fixture
def sink(client: httpx.AsyncClient) -> MemoryEventSink:
    return client.app.state.container.sink  # type: ignore[attr-defined,no-any-return]


# --- event builders ---------------------------------------------------------------

_COUNTER = iter(range(1, 1_000_000))


def taint_hit(event_id: str | None = None, **overrides: Any) -> dict[str, Any]:
    """A finding shaped exactly like the one the Java agent emits."""
    event: dict[str, Any] = {
        "event_id": event_id or f"evt-{next(_COUNTER):06d}",
        "type": "EVENT_TYPE_TAINT_HIT",
        "occurred_at_ms": 1785000000000,
        "monotonic_nanos": 123456789,
        "trace_id": "demo-trace-1",
        "taint_hit": {
            "rule_key": "sql-injection",
            "severity": "SEVERITY_CRITICAL",
            "confidence": "CONFIDENCE_EXPLOITED",
            "sink_signature": "java.sql.Statement#execute(String)",
            "sink_argument": "SELECT name FROM users WHERE name = '' OR 1=1--'",
            "stack_fingerprint": "637756f7a8203e327221954c",
            "imprecise": False,
            "ranges": [
                {
                    "start": 37,
                    "length": 10,
                    "source": "SOURCE_KIND_PARAMETER",
                    "source_name": "name",
                }
            ],
            "stack": [
                {
                    "declaring_class": "com.acme.UserRepository",
                    "method_name": "findByNameUnsafe",
                    "line_number": 88,
                    "application_code": True,
                }
            ],
            "sanitizers_applied": [],
        },
    }
    event.update(overrides)
    return event


def route_event(event_id: str | None = None) -> dict[str, Any]:
    return {
        "event_id": event_id or f"evt-{next(_COUNTER):06d}",
        "type": "EVENT_TYPE_ROUTE",
        "occurred_at_ms": 1785000000000,
        "monotonic_nanos": 1,
        "trace_id": "",
        "route": {"method": "GET", "path_template": "/users", "authenticated": True},
    }


def ndjson(*events: dict[str, Any]) -> bytes:
    return ("\n".join(json.dumps(event) for event in events) + "\n").encode("utf-8")


@pytest.fixture
def make_ndjson() -> Iterator[Any]:
    yield ndjson
