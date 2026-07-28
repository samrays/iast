"""Operator procedures: seeding, chain verification, fleet sweep, session purge."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text
from tests.conftest import Tenant, register_tenant

from aegis_api import operations
from aegis_api.container import Container
from aegis_api.domain.entities import AgentStatus, LicenseTier
from aegis_api.domain.errors import ConflictError, NotFoundError
from aegis_api.domain.value_objects import Slug

pytestmark = pytest.mark.integration


class TestSeed:
    async def test_creates_an_organization_with_a_generated_password(
        self, container: Container
    ) -> None:
        suffix = uuid4().hex[:8]
        result = await operations.seed_organization(
            container,
            organization=f"Seeded {suffix}",
            email=f"seeded-{suffix}@example.com",
            full_name="Seed Owner",
        )
        assert result.password_was_generated
        assert len(result.password) == 24
        assert result.organization_slug.startswith("seeded-")

    async def test_accepts_an_explicit_password(self, container: Container) -> None:
        suffix = uuid4().hex[:8]
        result = await operations.seed_organization(
            container,
            organization=f"Explicit {suffix}",
            email=f"explicit-{suffix}@example.com",
            full_name="Explicit Owner",
            password="a-deliberately-chosen-passphrase",
            tier=LicenseTier.BUSINESS,
        )
        assert not result.password_was_generated
        assert result.password == "a-deliberately-chosen-passphrase"

    async def test_refuses_to_overwrite_an_existing_account(
        self, container: Container, tenant: Tenant
    ) -> None:
        # A bootstrap command that silently reset an owner's password would be a backdoor.
        with pytest.raises(ConflictError):
            await operations.seed_organization(
                container,
                organization="Duplicate Seed",
                email=tenant.email,
                full_name="Impostor",
            )

    async def test_generated_passwords_are_unique(self) -> None:
        assert len({operations.generate_password() for _ in range(200)}) == 200


class TestVerifyAuditChain:
    async def test_reports_an_intact_chain(
        self, container: Container, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        status = await operations.verify_audit_chain(container, organization_slug=tenant.slug)
        assert status.intact
        assert status.entries_checked >= 2
        assert status.first_broken_sequence is None

    async def test_detects_a_tampered_entry(
        self, container: Container, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        # Tamper as a superuser would have to: the application role cannot UPDATE this
        # table, so the test uses the admin connection deliberately.
        from sqlalchemy.ext.asyncio import create_async_engine
        from tests.conftest import _admin_url

        engine = create_async_engine(_admin_url(), poolclass=None)
        async with engine.begin() as connection:
            await connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only")
            )
            await connection.execute(
                text(
                    "UPDATE audit_events SET action = 'tampered' "
                    "WHERE organization_id = :org AND sequence = 1"
                ),
                {"org": tenant.organization_id},
            )
            await connection.execute(
                text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only")
            )
        await engine.dispose()

        status = await operations.verify_audit_chain(container, organization_slug=tenant.slug)
        assert not status.intact
        assert status.first_broken_sequence == 1

    async def test_unknown_organization_raises(self, container: Container) -> None:
        with pytest.raises(NotFoundError):
            await operations.verify_audit_chain(container, organization_slug="no-such-tenant")


class TestSweepOfflineAgents:
    async def test_demotes_agents_that_stopped_reporting(
        self, container: Container, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        key = await client.post(
            "/api/v1/api-keys",
            headers=tenant.headers,
            json={"name": "k", "permissions": ["agent:write"], "expires_in_days": 30},
        )
        registered = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {key.json()['secret']}"},
            json={
                "application_name": "Sweepable",
                "environment": "PRODUCTION",
                "language": "JAVA",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "sweep-1",
                "agent_version": "0.4.0",
                "runtime_version": "21",
            },
        )
        agent_headers = {"Authorization": f"Bearer {registered.json()['agent_token']}"}
        await client.post(
            "/api/v1/agents/heartbeat", headers=agent_headers, json={"cpu_overhead_pct": 1.0}
        )

        # Nothing to do while the heartbeat is fresh.
        assert await operations.sweep_offline_agents(container, organization_slug=tenant.slug) == 0

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(tenant.organization_id)
            await uow.session.execute(
                text(
                    "UPDATE agents SET last_seen_at = last_seen_at - interval '10 minutes' "
                    "WHERE organization_id = :org"
                ),
                {"org": tenant.organization_id},
            )
            await uow.commit()

        assert await operations.sweep_offline_agents(container, organization_slug=tenant.slug) == 1

        agent_id = registered.json()["agent"]["id"]
        after = await client.get(f"/api/v1/agents/{agent_id}", headers=tenant.headers)
        assert after.json()["status"] == AgentStatus.OFFLINE.value

    async def test_unknown_organization_raises(self, container: Container) -> None:
        with pytest.raises(NotFoundError):
            await operations.sweep_offline_agents(container, organization_slug="no-such-tenant")


class TestPurgeExpiredSessions:
    async def test_removes_only_long_expired_rows(
        self, container: Container, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        assert login.status_code == 200
        client.cookies.clear()

        # A live session survives the purge.
        assert await operations.purge_expired_sessions(container) >= 0
        async with container.unit_of_work() as uow:
            live = (
                await uow.session.execute(
                    text("SELECT count(*) FROM sessions WHERE organization_id = :org"),
                    {"org": tenant.organization_id},
                )
            ).scalar_one()
        assert live >= 1

        cutoff = container.auth.clock.now() - timedelta(days=3)
        async with container.unit_of_work() as uow:
            await uow.session.execute(
                text("UPDATE sessions SET expires_at = :cutoff WHERE organization_id = :org"),
                {"cutoff": cutoff, "org": tenant.organization_id},
            )
            await uow.commit()

        assert await operations.purge_expired_sessions(container) >= 1
        async with container.unit_of_work() as uow:
            remaining = (
                await uow.session.execute(
                    text("SELECT count(*) FROM sessions WHERE organization_id = :org"),
                    {"org": tenant.organization_id},
                )
            ).scalar_one()
        assert remaining == 0


class TestDescribeRoutes:
    async def test_lists_every_registered_route(self, client: httpx.AsyncClient) -> None:
        described = operations.describe_routes(client.app)  # type: ignore[attr-defined]
        paths = {path for _, path in described}
        assert "/api/v1/auth/login" in paths
        assert "/api/v1/applications" in paths
        assert "/healthz" in paths
        # Every entry carries at least one concrete method.
        assert all(methods for methods, _ in described)


class TestSlugHelper:
    async def test_slug_round_trips_through_the_repository(
        self, container: Container, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        async with container.unit_of_work() as uow:
            found = await uow.organizations.get_by_slug(Slug(tenant.slug))
        assert found is not None
        assert str(found.id) == tenant.organization_id
