"""Cross-tenant isolation (ADR-0003, threat T-09).

Two independent controls must both hold: the repository predicate and PostgreSQL row-level
security. These tests attack each of them directly.
"""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text
from tests.conftest import Tenant, create_application, register_tenant, role_id_for

from aegis_api.container import Container

pytestmark = [pytest.mark.integration, pytest.mark.security]


class TestCrossTenantAccess:
    async def test_application_of_another_tenant_is_not_found(
        self, client: httpx.AsyncClient, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        victim = await create_application(client, tenant, name="Victim Service")

        response = await client.get(
            f"/api/v1/applications/{victim['id']}", headers=other_tenant.headers
        )
        # 404 rather than 403: a 403 would confirm the resource exists.
        assert response.status_code == 404
        assert response.json()["code"] == "not_found"

    async def test_cannot_update_or_delete_another_tenants_application(
        self, client: httpx.AsyncClient, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        victim = await create_application(client, tenant, name="Untouchable")

        patched = await client.patch(
            f"/api/v1/applications/{victim['id']}",
            headers=other_tenant.headers,
            json={"criticality": "LOW"},
        )
        assert patched.status_code == 404

        deleted = await client.delete(
            f"/api/v1/applications/{victim['id']}", headers=other_tenant.headers
        )
        assert deleted.status_code == 404

        # The victim's record is untouched.
        still_there = await client.get(
            f"/api/v1/applications/{victim['id']}", headers=tenant.headers
        )
        assert still_there.status_code == 200
        assert still_there.json()["criticality"] == "HIGH"

    async def test_listings_never_leak_across_tenants(self, client: httpx.AsyncClient) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        await create_application(client, alpha, name="Alpha Only")
        await create_application(client, beta, name="Beta Only")

        alpha_apps = await client.get("/api/v1/applications", headers=alpha.headers)
        beta_apps = await client.get("/api/v1/applications", headers=beta.headers)
        assert [a["name"] for a in alpha_apps.json()["items"]] == ["Alpha Only"]
        assert [a["name"] for a in beta_apps.json()["items"]] == ["Beta Only"]

    async def test_roles_are_not_visible_across_tenants(self, client: httpx.AsyncClient) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        alpha_viewer = await role_id_for(client, alpha, "Viewer")

        # Beta cannot assign a role belonging to Alpha.
        response = await client.post(
            "/api/v1/organizations/current/members/invite",
            headers=beta.headers,
            json={
                "email": f"cross-{uuid4().hex[:8]}@example.com",
                "full_name": "Cross",
                "role_ids": [alpha_viewer],
            },
        )
        assert response.status_code == 404

    async def test_members_are_not_visible_across_tenants(self, client: httpx.AsyncClient) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        alpha_members = await client.get(
            "/api/v1/organizations/current/members", headers=alpha.headers
        )
        membership_id = alpha_members.json()["items"][0]["membership_id"]

        response = await client.delete(
            f"/api/v1/organizations/current/members/{membership_id}", headers=beta.headers
        )
        assert response.status_code == 404

    async def test_audit_entries_are_not_visible_across_tenants(
        self, client: httpx.AsyncClient
    ) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        await create_application(client, alpha, name="Audited Alpha")

        beta_audit = await client.get("/api/v1/audit-events", headers=beta.headers)
        assert beta_audit.status_code == 200
        actions = {e["action"] for e in beta_audit.json()["items"]}
        assert "application.created" not in actions

    async def test_agents_are_not_visible_across_tenants(self, client: httpx.AsyncClient) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        key = await client.post(
            "/api/v1/api-keys",
            headers=alpha.headers,
            json={"name": "k", "permissions": ["agent:write"], "expires_in_days": 30},
        )
        registered = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {key.json()['secret']}"},
            json={
                "application_name": "Alpha Agent App",
                "environment": "PRODUCTION",
                "language": "JAVA",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "h",
                "agent_version": "0.4.0",
                "runtime_version": "21",
            },
        )
        agent_id = registered.json()["agent"]["id"]
        response = await client.get(f"/api/v1/agents/{agent_id}", headers=beta.headers)
        assert response.status_code == 404

    async def test_api_key_of_one_tenant_cannot_reach_another(
        self, client: httpx.AsyncClient
    ) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        victim = await create_application(client, beta, name="Beta Secret")

        key = await client.post(
            "/api/v1/api-keys",
            headers=alpha.headers,
            json={"name": "k", "permissions": ["app:read"], "expires_in_days": 30},
        )
        response = await client.get(
            f"/api/v1/applications/{victim['id']}",
            headers={"Authorization": f"Bearer {key.json()['secret']}"},
        )
        assert response.status_code == 404


class TestRowLevelSecurity:
    """Attack the database directly, bypassing every repository."""

    async def test_rls_hides_rows_when_a_different_tenant_is_bound(
        self, client: httpx.AsyncClient, container: Container
    ) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)
        await create_application(client, alpha, name="RLS Guarded")

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(beta.organization_id)
            # A raw statement with no tenant predicate at all — the policy is the only
            # thing standing between this query and another tenant's rows.
            rows = (await uow.session.execute(text("SELECT id, name FROM applications"))).fetchall()
            assert all(row.name != "RLS Guarded" for row in rows)

    async def test_rls_returns_nothing_when_no_tenant_is_bound(
        self, client: httpx.AsyncClient, container: Container
    ) -> None:
        alpha = await register_tenant(client)
        await create_application(client, alpha, name="Unbound Check")

        async with container.unit_of_work() as uow:
            rows = (await uow.session.execute(text("SELECT id FROM applications"))).fetchall()
            # Failing closed: an unset GUC yields no rows rather than every row.
            assert rows == []

    async def test_rls_blocks_writing_into_another_tenant(
        self, client: httpx.AsyncClient, container: Container
    ) -> None:
        alpha = await register_tenant(client)
        beta = await register_tenant(client)

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(beta.organization_id)
            with pytest.raises(Exception, match=r"row-level security|violates"):
                await uow.session.execute(
                    text(
                        "INSERT INTO applications "
                        "(id, organization_id, name, slug, language, criticality, tags, "
                        " description, created_at, updated_at) "
                        "VALUES (gen_random_uuid(), :org, 'Injected', 'injected', 'GO', "
                        "'LOW', '{}', '', now(), now())"
                    ),
                    {"org": alpha.organization_id},
                )

    async def test_tenant_repositories_are_unavailable_before_binding(
        self, container: Container
    ) -> None:
        from aegis_api.infrastructure.db.unit_of_work import TenantNotBoundError

        async with container.unit_of_work() as uow:
            with pytest.raises(TenantNotBoundError):
                _ = uow.applications
            with pytest.raises(TenantNotBoundError):
                _ = uow.audit
