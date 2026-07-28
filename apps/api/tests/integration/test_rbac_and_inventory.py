"""Members, roles, API keys, application inventory and the agent fleet."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from tests.conftest import Tenant, create_application, register_tenant, role_id_for

pytestmark = pytest.mark.integration


class TestRoles:
    async def test_five_system_roles_are_seeded(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.get("/api/v1/organizations/current/roles", headers=tenant.headers)
        assert response.status_code == 200
        names = {r["name"] for r in response.json()}
        assert names == {"Owner", "Admin", "Security Analyst", "Developer", "Viewer"}
        assert all(r["is_system"] for r in response.json())

    async def test_viewer_role_is_read_only(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        roles = (
            await client.get("/api/v1/organizations/current/roles", headers=tenant.headers)
        ).json()
        viewer = next(r for r in roles if r["name"] == "Viewer")
        assert all(p.endswith(":read") for p in viewer["permissions"])

    async def test_create_update_and_delete_a_custom_role(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        created = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={
                "name": "Release Manager",
                "description": "Ships things",
                "permissions": ["app:read", "agent:read"],
            },
        )
        assert created.status_code == 201
        role_id = created.json()["id"]

        updated = await client.patch(
            f"/api/v1/organizations/current/roles/{role_id}",
            headers=tenant.headers,
            json={"permissions": ["app:read", "agent:read", "finding:read"]},
        )
        assert updated.status_code == 200
        assert set(updated.json()["permissions"]) == {"app:read", "agent:read", "finding:read"}

        deleted = await client.delete(
            f"/api/v1/organizations/current/roles/{role_id}", headers=tenant.headers
        )
        assert deleted.status_code == 204

    async def test_system_roles_cannot_be_modified(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        owner_role = await role_id_for(client, tenant, "Owner")
        response = await client.patch(
            f"/api/v1/organizations/current/roles/{owner_role}",
            headers=tenant.headers,
            json={"name": "Superuser"},
        )
        assert response.status_code == 409

    async def test_duplicate_role_names_conflict(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        payload = {"name": "Duplicate", "description": "", "permissions": ["app:read"]}
        assert (
            await client.post(
                "/api/v1/organizations/current/roles", headers=tenant.headers, json=payload
            )
        ).status_code == 201
        second = await client.post(
            "/api/v1/organizations/current/roles", headers=tenant.headers, json=payload
        )
        assert second.status_code == 409

    async def test_unknown_permission_is_rejected(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        # Silently dropping a typo would create a role weaker than the admin believes.
        response = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={"name": f"Typo {uuid4().hex[:6]}", "permissions": ["app:reed"]},
        )
        assert response.status_code == 422
        assert "app:reed" in response.json()["detail"]

    async def test_role_in_use_cannot_be_deleted(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        role = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={"name": "In Use", "permissions": ["app:read"]},
        )
        role_id = role.json()["id"]
        await client.post(
            "/api/v1/organizations/current/members/invite",
            headers=tenant.headers,
            json={
                "email": f"member-{uuid4().hex[:8]}@example.com",
                "full_name": "Member",
                "role_ids": [role_id],
            },
        )
        response = await client.delete(
            f"/api/v1/organizations/current/roles/{role_id}", headers=tenant.headers
        )
        assert response.status_code == 409

    async def test_permission_catalogue_is_available(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.get("/api/v1/permissions", headers=tenant.headers)
        assert response.status_code == 200
        values = {entry["value"] for entry in response.json()}
        assert {"app:read", "finding:triage", "role:write"} <= values
        assert any(entry["privileged"] for entry in response.json())


class TestMembers:
    async def test_invite_list_update_and_remove(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        viewer = await role_id_for(client, tenant, "Viewer")
        developer = await role_id_for(client, tenant, "Developer")

        invited = await client.post(
            "/api/v1/organizations/current/members/invite",
            headers=tenant.headers,
            json={
                "email": f"invitee-{uuid4().hex[:8]}@example.com",
                "full_name": "Invitee",
                "role_ids": [viewer],
            },
        )
        assert invited.status_code == 201
        assert invited.json()["status"] == "INVITED"
        membership_id = invited.json()["membership_id"]

        listed = await client.get("/api/v1/organizations/current/members", headers=tenant.headers)
        assert listed.status_code == 200
        assert len(listed.json()["items"]) == 2

        promoted = await client.patch(
            f"/api/v1/organizations/current/members/{membership_id}",
            headers=tenant.headers,
            json={"role_ids": [developer]},
        )
        assert promoted.status_code == 200
        assert [r["name"] for r in promoted.json()["roles"]] == ["Developer"]

        removed = await client.delete(
            f"/api/v1/organizations/current/members/{membership_id}", headers=tenant.headers
        )
        assert removed.status_code == 204

    async def test_cannot_invite_the_same_person_twice(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        viewer = await role_id_for(client, tenant, "Viewer")
        email = f"twice-{uuid4().hex[:8]}@example.com"
        payload = {"email": email, "full_name": "Twice", "role_ids": [viewer]}
        assert (
            await client.post(
                "/api/v1/organizations/current/members/invite",
                headers=tenant.headers,
                json=payload,
            )
        ).status_code == 201
        second = await client.post(
            "/api/v1/organizations/current/members/invite", headers=tenant.headers, json=payload
        )
        assert second.status_code == 409

    async def test_owner_cannot_remove_themselves(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        members = await client.get("/api/v1/organizations/current/members", headers=tenant.headers)
        membership_id = members.json()["items"][0]["membership_id"]
        response = await client.delete(
            f"/api/v1/organizations/current/members/{membership_id}", headers=tenant.headers
        )
        assert response.status_code == 409

    async def test_last_owner_cannot_be_demoted(self, client: httpx.AsyncClient) -> None:
        # Demoting the last Owner would leave the organization unadministrable.
        tenant = await register_tenant(client)
        viewer = await role_id_for(client, tenant, "Viewer")
        members = await client.get("/api/v1/organizations/current/members", headers=tenant.headers)
        membership_id = members.json()["items"][0]["membership_id"]
        response = await client.patch(
            f"/api/v1/organizations/current/members/{membership_id}",
            headers=tenant.headers,
            json={"role_ids": [viewer]},
        )
        assert response.status_code == 409


class TestOrganization:
    async def test_read_and_update(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        assert (
            await client.get("/api/v1/organizations/current", headers=tenant.headers)
        ).status_code == 200

        updated = await client.patch(
            "/api/v1/organizations/current",
            headers=tenant.headers,
            json={"name": "Renamed Organization", "settings": {"capture_request_body": "NONE"}},
        )
        assert updated.status_code == 200
        assert updated.json()["name"] == "Renamed Organization"


class TestApiKeys:
    async def test_issue_list_and_revoke(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        created = await client.post(
            "/api/v1/api-keys",
            headers=tenant.headers,
            json={"name": "ci-pipeline", "permissions": ["app:read"], "expires_in_days": 30},
        )
        assert created.status_code == 201
        secret = created.json()["secret"]
        assert secret.startswith("ak_") and "." in secret

        listed = await client.get("/api/v1/api-keys", headers=tenant.headers)
        assert listed.status_code == 200
        # The plaintext secret is returned once and never stored.
        assert "secret" not in listed.json()[0]

        key_id = created.json()["api_key"]["id"]
        assert (
            await client.delete(f"/api/v1/api-keys/{key_id}", headers=tenant.headers)
        ).status_code == 204
        # A revoked key stops working immediately.
        assert (
            await client.get("/api/v1/applications", headers={"Authorization": f"Bearer {secret}"})
        ).status_code == 401

    async def test_api_key_authenticates_within_its_permissions(
        self, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        created = await client.post(
            "/api/v1/api-keys",
            headers=tenant.headers,
            json={"name": "read-only", "permissions": ["app:read"], "expires_in_days": 30},
        )
        headers = {"Authorization": f"Bearer {created.json()['secret']}"}
        assert (await client.get("/api/v1/applications", headers=headers)).status_code == 200
        # It holds app:read but not app:write.
        forbidden = await client.post(
            "/api/v1/applications",
            headers=headers,
            json={"name": "Nope", "language": "GO"},
        )
        assert forbidden.status_code == 403

    async def test_garbage_key_is_rejected(self, client: httpx.AsyncClient) -> None:
        for candidate in ("ak_short.secret", "ak_", "ak_abcdefghijkl.wrong", "nonsense"):
            response = await client.get(
                "/api/v1/applications", headers={"Authorization": f"Bearer {candidate}"}
            )
            assert response.status_code == 401


class TestApplications:
    async def test_create_read_update_delete(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        created = await create_application(client, tenant, name="Ledger Service")
        assert created["slug"] == "ledger-service"
        assert created["tags"] == ["payments"]
        assert len(created["environments"]) == 1

        fetched = await client.get(f"/api/v1/applications/{created['id']}", headers=tenant.headers)
        assert fetched.status_code == 200

        updated = await client.patch(
            f"/api/v1/applications/{created['id']}",
            headers=tenant.headers,
            json={"criticality": "CRITICAL", "tags": ["payments", "pci"]},
        )
        assert updated.status_code == 200
        assert updated.json()["criticality"] == "CRITICAL"
        assert set(updated.json()["tags"]) == {"payments", "pci"}

        assert (
            await client.delete(f"/api/v1/applications/{created['id']}", headers=tenant.headers)
        ).status_code == 204
        assert (
            await client.get(f"/api/v1/applications/{created['id']}", headers=tenant.headers)
        ).status_code == 404

    async def test_duplicate_slug_conflicts(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        await create_application(client, tenant, name="Duplicate App")
        response = await client.post(
            "/api/v1/applications",
            headers=tenant.headers,
            json={"name": "Duplicate App", "language": "PYTHON"},
        )
        assert response.status_code == 409

    async def test_invalid_tag_is_rejected(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        response = await client.post(
            "/api/v1/applications",
            headers=tenant.headers,
            json={"name": "Tagged", "language": "NODE", "tags": ["not a tag"]},
        )
        assert response.status_code == 422

    async def test_search_and_tag_filters(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        await create_application(client, tenant, name="Alpha Service")
        await create_application(client, tenant, name="Beta Service")

        found = await client.get(
            "/api/v1/applications", headers=tenant.headers, params={"q": "alpha"}
        )
        assert [a["name"] for a in found.json()["items"]] == ["Alpha Service"]

        tagged = await client.get(
            "/api/v1/applications", headers=tenant.headers, params={"tag": "payments"}
        )
        assert len(tagged.json()["items"]) == 2

    async def test_cursor_pagination_walks_the_whole_set(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        # Three, because a TRIAL licence entitles the tenant to exactly three applications.
        for index in range(3):
            await create_application(client, tenant, name=f"Paged {index}")

        seen: list[str] = []
        cursor: str | None = None
        while True:
            params: dict[str, object] = {"limit": 1}
            if cursor:
                params["cursor"] = cursor
            page = await client.get("/api/v1/applications", headers=tenant.headers, params=params)
            assert page.status_code == 200
            seen.extend(item["id"] for item in page.json()["items"])
            cursor = page.json()["page"]["next_cursor"]
            if not cursor:
                break

        assert len(seen) == 3
        assert len(set(seen)) == 3

    async def test_trial_licence_caps_application_count(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        for index in range(3):
            await create_application(client, tenant, name=f"Capped {index}")
        response = await client.post(
            "/api/v1/applications",
            headers=tenant.headers,
            json={"name": "One Too Many", "language": "GO"},
        )
        assert response.status_code == 402
        assert response.json()["code"] == "license_limit_exceeded"

    async def test_malformed_cursor_is_rejected(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.get(
            "/api/v1/applications", headers=tenant.headers, params={"cursor": "!!!not-base64!!!"}
        )
        assert response.status_code == 422

    async def test_environments_can_be_added(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        application = await create_application(client, tenant, name="Multi Env")
        added = await client.post(
            f"/api/v1/applications/{application['id']}/environments",
            headers=tenant.headers,
            json={"kind": "STAGING", "internet_facing": False},
        )
        assert added.status_code == 201

        duplicate = await client.post(
            f"/api/v1/applications/{application['id']}/environments",
            headers=tenant.headers,
            json={"kind": "STAGING", "internet_facing": False},
        )
        assert duplicate.status_code == 409

        listed = await client.get(
            f"/api/v1/applications/{application['id']}/environments", headers=tenant.headers
        )
        assert {e["kind"] for e in listed.json()} == {"PRODUCTION", "STAGING"}


class TestAgents:
    async def _api_key(self, client: httpx.AsyncClient, tenant: Tenant) -> str:
        created = await client.post(
            "/api/v1/api-keys",
            headers=tenant.headers,
            json={
                "name": "agent-bootstrap",
                "permissions": ["agent:write", "agent:read", "app:read"],
                "expires_in_days": 30,
            },
        )
        assert created.status_code == 201
        return str(created.json()["secret"])

    async def test_registration_discovers_the_application(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        key = await self._api_key(client, tenant)
        response = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "application_name": "Discovered Service",
                "environment": "PRODUCTION",
                "language": "PYTHON",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "worker-1",
                "agent_version": "0.4.0",
                "runtime_version": "3.12.4",
            },
        )
        assert response.status_code == 201
        assert response.json()["heartbeat_interval_seconds"] == 30

        # An agent showing up for an unknown service is how inventory gets populated.
        applications = await client.get("/api/v1/applications", headers=tenant.headers)
        assert any(a["name"] == "Discovered Service" for a in applications.json()["items"])

    async def test_reregistration_reuses_the_fingerprint(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        key = await self._api_key(client, tenant)
        fingerprint = f"fp-{uuid4().hex}"
        payload = {
            "application_name": "Restarting Service",
            "environment": "PRODUCTION",
            "language": "JAVA",
            "fingerprint": fingerprint,
            "hostname": "pod-1",
            "agent_version": "0.4.0",
            "runtime_version": "21",
        }
        headers = {"Authorization": f"Bearer {key}"}
        first = await client.post("/api/v1/agents/register", headers=headers, json=payload)
        second = await client.post(
            "/api/v1/agents/register", headers=headers, json={**payload, "agent_version": "0.4.1"}
        )
        # A pod restart must not create a new agent row on every deploy.
        assert first.json()["agent"]["id"] == second.json()["agent"]["id"]
        assert second.json()["agent"]["agent_version"] == "0.4.1"

    async def test_heartbeat_updates_status_and_config(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        key = await self._api_key(client, tenant)
        registered = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "application_name": "Beating Service",
                "environment": "STAGING",
                "language": "NODE",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "node-1",
                "agent_version": "0.4.0",
                "runtime_version": "22",
            },
        )
        agent_headers = {"Authorization": f"Bearer {registered.json()['agent_token']}"}

        healthy = await client.post(
            "/api/v1/agents/heartbeat",
            headers=agent_headers,
            json={"cpu_overhead_pct": 1.5, "memory_mb": 64, "events_sent": 100},
        )
        assert healthy.json()["status"] == "ONLINE"

        degraded = await client.post(
            "/api/v1/agents/heartbeat",
            headers=agent_headers,
            json={"cpu_overhead_pct": 8.0, "memory_mb": 200, "events_dropped": 5},
        )
        assert degraded.json()["status"] == "DEGRADED"
        assert degraded.json()["events_sent"] == 100

        config = await client.get("/api/v1/agents/config", headers=agent_headers)
        assert config.status_code == 200
        assert "password" in config.json()["redact_keys"]
        assert config.json()["protection_mode"] == "MONITOR"
        assert "sql-injection" in config.json()["enabled_rules"]

    async def test_fleet_listing_and_administration(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        key = await self._api_key(client, tenant)
        registered = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "application_name": "Managed Service",
                "environment": "QA",
                "language": "GO",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "go-1",
                "agent_version": "0.4.0",
                "runtime_version": "1.23",
            },
        )
        agent_id = registered.json()["agent"]["id"]
        agent_headers = {"Authorization": f"Bearer {registered.json()['agent_token']}"}

        listed = await client.get("/api/v1/agents", headers=tenant.headers)
        assert listed.status_code == 200
        assert any(a["id"] == agent_id for a in listed.json()["items"])

        assert (
            await client.get(f"/api/v1/agents/{agent_id}", headers=tenant.headers)
        ).status_code == 200

        disabled = await client.patch(
            f"/api/v1/agents/{agent_id}",
            headers=tenant.headers,
            json={"enabled": False, "pinned_version": "0.4.0"},
        )
        assert disabled.json()["status"] == "DISABLED"
        assert disabled.json()["pinned_version"] == "0.4.0"

        # A disabled agent's credential stops working — the kill switch.
        assert (
            await client.post("/api/v1/agents/heartbeat", headers=agent_headers, json={})
        ).status_code == 401

    async def test_registration_requires_agent_write(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        created = await client.post(
            "/api/v1/api-keys",
            headers=tenant.headers,
            json={"name": "weak", "permissions": ["app:read"], "expires_in_days": 30},
        )
        response = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {created.json()['secret']}"},
            json={
                "application_name": "Denied",
                "environment": "QA",
                "language": "GO",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "h",
                "agent_version": "0.4.0",
                "runtime_version": "1.23",
            },
        )
        assert response.status_code == 403
