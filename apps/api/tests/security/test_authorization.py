"""Privilege escalation, permission enforcement and lockout (threats T-07, T-10)."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from tests.conftest import TEST_PASSWORD, Tenant, register_tenant, role_id_for

pytestmark = [pytest.mark.integration, pytest.mark.security]


async def _member_session(
    client: httpx.AsyncClient, tenant: Tenant, role_name: str
) -> dict[str, str]:
    """Invite a member with one role, set their password, and sign them in."""
    role = await role_id_for(client, tenant, role_name)
    email = f"member-{uuid4().hex[:10]}@example.com"
    invited = await client.post(
        "/api/v1/organizations/current/members/invite",
        headers=tenant.headers,
        json={"email": email, "full_name": role_name, "role_ids": [role]},
    )
    assert invited.status_code == 201

    # An invited user has no password yet. The Owner is the only path to a credential in
    # Phase 2 (the emailed invitation flow lands with the dashboard in Phase 3), so the
    # test drives the same use case the invitation link will.
    from aegis_api.application.context import RequestContext

    app = client.app  # type: ignore[attr-defined]
    container = app.state.container
    async with container.unit_of_work() as uow:
        from aegis_api.domain.value_objects import EmailAddress, PasswordHash

        user = await uow.users.get_by_email(EmailAddress(email))
        assert user is not None
        user.set_password(
            PasswordHash(container.auth.hasher.hash(TEST_PASSWORD)), container.auth.clock.now()
        )
        await uow.users.update(user)
        await uow.bind_tenant(tenant.organization_id)
        membership = await uow.memberships.get_for_user(user.id)
        assert membership is not None
        membership.activate(container.auth.clock.now())
        await uow.memberships.update(membership)
        await uow.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": TEST_PASSWORD, "organization_slug": tenant.slug},
    )
    assert login.status_code == 200, login.text
    client.cookies.clear()
    _ = RequestContext  # imported for documentation of the flow being exercised
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


class TestPermissionEnforcement:
    async def test_viewer_cannot_write(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        viewer = await _member_session(client, tenant, "Viewer")

        assert (await client.get("/api/v1/applications", headers=viewer)).status_code == 200
        created = await client.post(
            "/api/v1/applications",
            headers=viewer,
            json={"name": "Viewer Attempt", "language": "GO"},
        )
        assert created.status_code == 403
        assert created.json()["code"] == "permission_denied"

    async def test_viewer_cannot_read_the_audit_log(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        viewer = await _member_session(client, tenant, "Viewer")
        assert (await client.get("/api/v1/audit-events", headers=viewer)).status_code == 403

    async def test_developer_cannot_manage_roles(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        developer = await _member_session(client, tenant, "Developer")
        response = await client.post(
            "/api/v1/organizations/current/roles",
            headers=developer,
            json={"name": "Escalated", "permissions": ["app:read"]},
        )
        assert response.status_code == 403

    async def test_developer_cannot_issue_api_keys(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        developer = await _member_session(client, tenant, "Developer")
        response = await client.post(
            "/api/v1/api-keys",
            headers=developer,
            json={"name": "sneaky", "permissions": ["app:read"], "expires_in_days": 30},
        )
        assert response.status_code == 403

    async def test_security_analyst_can_triage_but_not_delete_the_organization(
        self, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        analyst = await _member_session(client, tenant, "Security Analyst")
        me = await client.get("/api/v1/auth/me", headers=analyst)
        permissions = set(me.json()["permissions"])
        assert "finding:triage" in permissions
        assert "audit:read" in permissions
        assert "org:delete" not in permissions


class TestPrivilegeEscalation:
    async def test_cannot_create_a_role_beyond_own_permissions(
        self, client: httpx.AsyncClient
    ) -> None:
        # Without this rule, ``role:write`` would be equivalent to ownership.
        tenant = await register_tenant(client)
        limited_role = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={"name": "Role Editor", "permissions": ["role:write", "app:read"]},
        )
        assert limited_role.status_code == 201

        editor_headers = await _member_session_with_role(client, tenant, limited_role.json()["id"])
        attempt = await client.post(
            "/api/v1/organizations/current/roles",
            headers=editor_headers,
            json={"name": "Superuser", "permissions": ["role:write", "settings:write"]},
        )
        assert attempt.status_code == 403
        assert attempt.json()["code"] == "privilege_escalation"
        assert "settings:write" in attempt.json()["missing_permissions"]

    async def test_cannot_assign_a_role_beyond_own_permissions(
        self, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        limited_role = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={
                "name": "Inviter",
                "permissions": ["role:write", "user:invite", "app:read", "org:read"],
            },
        )
        inviter = await _member_session_with_role(client, tenant, limited_role.json()["id"])
        admin_role = await role_id_for(client, tenant, "Admin")

        attempt = await client.post(
            "/api/v1/organizations/current/members/invite",
            headers=inviter,
            json={
                "email": f"escalated-{uuid4().hex[:8]}@example.com",
                "full_name": "Escalated",
                "role_ids": [admin_role],
            },
        )
        assert attempt.status_code == 403
        assert attempt.json()["code"] == "privilege_escalation"

    async def test_owner_only_permissions_cannot_enter_a_custom_role(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={"name": f"Deleter {uuid4().hex[:6]}", "permissions": ["org:delete"]},
        )
        assert response.status_code == 409

    async def test_api_key_cannot_exceed_the_issuers_permissions(
        self, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        role = await client.post(
            "/api/v1/organizations/current/roles",
            headers=tenant.headers,
            json={"name": "Key Issuer", "permissions": ["settings:write", "app:read"]},
        )
        issuer = await _member_session_with_role(client, tenant, role.json()["id"])
        attempt = await client.post(
            "/api/v1/api-keys",
            headers=issuer,
            json={"name": "over-scoped", "permissions": ["app:delete"], "expires_in_days": 30},
        )
        assert attempt.status_code == 403


class TestBruteForceProtection:
    async def test_repeated_failures_lock_the_account(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        for _ in range(5):
            response = await client.post(
                "/api/v1/auth/login",
                json={"email": tenant.email, "password": "definitely-not-it"},
            )
            assert response.status_code == 401

        locked = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        assert locked.status_code == 423
        assert locked.json()["code"] == "account_locked"
        # A client that respects Retry-After stops hammering the endpoint.
        assert int(locked.headers["Retry-After"]) > 0

    async def test_lockout_does_not_reveal_account_existence(
        self, client: httpx.AsyncClient
    ) -> None:
        unknown = f"ghost-{uuid4().hex[:8]}@example.com"
        for _ in range(6):
            response = await client.post(
                "/api/v1/auth/login", json={"email": unknown, "password": "whatever-value"}
            )
            # An unknown account never transitions to 423; that difference would be an
            # enumeration oracle in itself.
            assert response.status_code == 401


class TestSecurityHeaders:
    async def test_responses_carry_hardening_headers(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.get("/api/v1/auth/me", headers=tenant.headers)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Request-Id"]

    async def test_refresh_cookie_is_locked_down(self, client: httpx.AsyncClient) -> None:
        suffix = uuid4().hex[:10]
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "organization_name": f"Cookie {suffix}",
                "email": f"cookie-{suffix}@example.com",
                "password": TEST_PASSWORD,
                "full_name": "Cookie",
            },
        )
        cookie_header = response.headers["set-cookie"]
        assert "HttpOnly" in cookie_header
        assert "SameSite=strict" in cookie_header.replace("SameSite=Strict", "SameSite=strict")
        assert "Path=/api/v1/auth" in cookie_header
        client.cookies.clear()

    async def test_errors_use_the_problem_media_type(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/applications")
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.headers["WWW-Authenticate"].startswith("Bearer")
        body = response.json()
        assert {"type", "title", "status", "detail", "code", "request_id"} <= set(body)


async def _member_session_with_role(
    client: httpx.AsyncClient, tenant: Tenant, role_id: str
) -> dict[str, str]:
    email = f"custom-{uuid4().hex[:10]}@example.com"
    invited = await client.post(
        "/api/v1/organizations/current/members/invite",
        headers=tenant.headers,
        json={"email": email, "full_name": "Custom", "role_ids": [role_id]},
    )
    assert invited.status_code == 201, invited.text

    container = client.app.state.container  # type: ignore[attr-defined]
    async with container.unit_of_work() as uow:
        from aegis_api.domain.value_objects import EmailAddress, PasswordHash

        user = await uow.users.get_by_email(EmailAddress(email))
        assert user is not None
        user.set_password(
            PasswordHash(container.auth.hasher.hash(TEST_PASSWORD)), container.auth.clock.now()
        )
        await uow.users.update(user)
        await uow.bind_tenant(tenant.organization_id)
        membership = await uow.memberships.get_for_user(user.id)
        assert membership is not None
        membership.activate(container.auth.clock.now())
        await uow.memberships.update(membership)
        await uow.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": TEST_PASSWORD, "organization_slug": tenant.slug},
    )
    assert login.status_code == 200, login.text
    client.cookies.clear()
    return {"Authorization": f"Bearer {login.json()['access_token']}"}
