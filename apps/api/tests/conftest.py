"""Shared test fixtures.

Integration tests run against a real PostgreSQL database. There is no SQLite fallback and
that is deliberate: the schema depends on CITEXT, INET, JSONB, arrays and — most
importantly — row-level security, so a test that passed on SQLite would prove nothing about
the isolation guarantee it claims to cover.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from aegis_api.config import Environment, Settings, get_settings
from aegis_api.container import Container, build_container
from aegis_api.infrastructure.db.base import Base
from aegis_api.infrastructure.db.models import TENANT_TABLES
from aegis_api.main import create_app

TEST_PASSWORD = "correct-horse-battery-77"


#: Least-privilege role the application connects as. It matters: PostgreSQL superusers
#: bypass row-level security entirely, even with ``FORCE`` set, so a suite that connected
#: as ``postgres`` would pass every isolation test while proving nothing.
APP_ROLE = "aegis_app"
APP_ROLE_PASSWORD = "aegis_app_test"


def _admin_url() -> str:
    """Superuser URL used only to create the schema, the role and the policies."""
    return os.environ.get(
        "AEGIS_TEST_ADMIN_DATABASE_URL",
        "postgresql+asyncpg://postgres:CyberPlural2024!@localhost:5433/aegis_test",
    )


def _app_url() -> str:
    """The URL the application under test connects with — non-superuser."""
    admin = _admin_url()
    _, _, tail = admin.partition("://")
    _, _, host_and_db = tail.partition("@")
    return f"postgresql+asyncpg://{APP_ROLE}:{APP_ROLE_PASSWORD}@{host_and_db}"


def _test_settings() -> Settings:
    os.environ["AEGIS_TEST_DATABASE_URL"] = _app_url()
    get_settings.cache_clear()
    return Settings(
        environment=Environment.TEST,
        test_database_url=_app_url(),
        debug=True,
        log_level="WARNING",
        # Argon2 at production cost makes every login test take ~100 ms. The parameters
        # under test are the *policy* ones, not the cost ones, so the suite turns the cost
        # down and a dedicated unit test asserts the production defaults instead.
        argon2_time_cost=1,
        argon2_memory_cost_kib=8192,
        argon2_parallelism=1,
        allow_self_service_signup=True,
        metrics_enabled=False,
        cors_origins=[],
    )


@pytest.fixture(scope="session")
def settings() -> Settings:
    return _test_settings()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def _database(settings: Settings) -> AsyncIterator[None]:
    """Build the schema, the least-privilege role and the RLS policies, once per session."""
    engine = create_async_engine(_admin_url(), poolclass=None)
    async with engine.begin() as connection:
        await connection.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        await connection.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))
        await connection.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await _ensure_app_role(connection)
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
        await _apply_security_objects(connection)
        await _grant_app_role(connection)
    await engine.dispose()
    yield
    engine = create_async_engine(_admin_url(), poolclass=None)
    async with engine.begin() as connection:
        await connection.execute(
            text("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
        )
        await connection.run_sync(Base.metadata.drop_all)
    await engine.dispose()


async def _ensure_app_role(connection: Any) -> None:
    await connection.execute(text(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                    CREATE ROLE {APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                        PASSWORD '{APP_ROLE_PASSWORD}';
                END IF;
            END
            $$;
            """))


async def _grant_app_role(connection: Any) -> None:
    """Grant the application role exactly what it needs — and nothing on the audit table.

    ``audit_events`` gets INSERT and SELECT only, so the append-only guarantee holds at the
    privilege level as well as through the trigger (threat T-11).
    """
    database = str(connection.engine.url.database)
    await connection.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {APP_ROLE}"))
    await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))
    await connection.execute(
        text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}")
    )
    await connection.execute(
        text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")
    )
    await connection.execute(text(f"REVOKE UPDATE, DELETE ON audit_events FROM {APP_ROLE}"))


async def _apply_security_objects(connection: Any) -> None:
    """Mirror the security DDL from migration 0001.

    Duplicated rather than invoked via Alembic so the suite can build a schema from the
    ORM metadata. ``tests/integration/test_migrations.py`` separately asserts that the
    migration and the metadata agree.
    """
    predicate = (
        "organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        " OR current_setting('app.rls_bypass', true) = 'on'"
    )
    for table in TENANT_TABLES:
        await connection.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        await connection.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        await connection.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        await connection.execute(
            text(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING ({predicate}) WITH CHECK ({predicate})"
            )
        )
    await connection.execute(text("""
            CREATE OR REPLACE FUNCTION audit_events_reject_mutation()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'audit_events is append-only (%)', TG_OP
                    USING ERRCODE = 'insufficient_privilege';
            END;
            $$ LANGUAGE plpgsql;
            """))
    await connection.execute(
        text("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    )
    await connection.execute(text("""
            CREATE TRIGGER audit_events_append_only
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();
            """))


@pytest_asyncio.fixture(loop_scope="session")
async def container(settings: Settings, _database: None) -> AsyncIterator[Container]:
    built = build_container(settings)
    yield built
    await built.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def client(settings: Settings, _database: None) -> AsyncIterator[httpx.AsyncClient]:
    """An HTTP client wired straight to the ASGI app — no socket, no server process."""
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            http.app = app  # type: ignore[attr-defined]
            yield http


@dataclass
class Tenant:
    """A registered organization with its Owner's credentials, ready to make requests."""

    organization_id: str
    slug: str
    user_id: str
    email: str
    password: str
    access_token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


async def register_tenant(client: httpx.AsyncClient, *, name: str | None = None) -> Tenant:
    """Create a fresh organization. Each call is isolated from every other."""
    suffix = uuid4().hex[:10]
    display = name or f"Tenant {suffix}"
    email = f"owner-{suffix}@example.com"
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": display,
            "email": email,
            "password": TEST_PASSWORD,
            "full_name": "Test Owner",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    # The refresh cookie is scoped per tenant; drop it so one tenant's cookie does not ride
    # along on another tenant's requests within a shared client.
    client.cookies.clear()
    return Tenant(
        organization_id=body["organization"]["id"],
        slug=body["organization"]["slug"],
        user_id=body["user_id"],
        email=email,
        password=TEST_PASSWORD,
        access_token=body["tokens"]["access_token"],
    )


@pytest_asyncio.fixture(loop_scope="session")
async def tenant(client: httpx.AsyncClient) -> Tenant:
    return await register_tenant(client)


@pytest_asyncio.fixture(loop_scope="session")
async def other_tenant(client: httpx.AsyncClient) -> Tenant:
    return await register_tenant(client)


async def create_application(
    client: httpx.AsyncClient, tenant: Tenant, *, name: str = "Payments API"
) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/applications",
        headers=tenant.headers,
        json={
            "name": name,
            "language": "JAVA",
            "criticality": "HIGH",
            "tags": ["payments"],
            "environments": [{"kind": "PRODUCTION", "internet_facing": True}],
        },
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


async def role_id_for(client: httpx.AsyncClient, tenant: Tenant, name: str) -> str:
    response = await client.get("/api/v1/organizations/current/roles", headers=tenant.headers)
    assert response.status_code == 200, response.text
    for role in response.json():
        if role["name"] == name:
            return str(role["id"])
    raise AssertionError(f"No role named {name!r}")
