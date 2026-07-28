"""Refresh-token rotation, reuse detection and audience separation (ADR-0006, T-06/T-08)."""

from __future__ import annotations

import httpx
import pytest
from tests.conftest import Tenant, register_tenant

from aegis_api.container import Container

pytestmark = [pytest.mark.integration, pytest.mark.security]


async def _login(client: httpx.AsyncClient, tenant: Tenant) -> str:
    response = await client.post(
        "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
    )
    assert response.status_code == 200
    token = response.cookies.get("aegis_refresh")
    assert token
    client.cookies.clear()
    return str(token)


class TestRefreshReuseDetection:
    async def test_replaying_a_consumed_token_revokes_the_whole_family(
        self, client: httpx.AsyncClient, container: Container
    ) -> None:
        tenant = await register_tenant(client)
        original = await _login(client, tenant)

        first = await client.post("/api/v1/auth/refresh", json={"refresh_token": original})
        assert first.status_code == 200
        rotated = client.cookies.get("aegis_refresh")
        client.cookies.clear()

        # Outside the grace window, replaying a consumed token is theft, not a race. The
        # test forces that by ageing the rotation timestamp rather than by sleeping.
        await _age_rotation(container, tenant)

        replayed = await client.post("/api/v1/auth/refresh", json={"refresh_token": original})
        assert replayed.status_code == 401
        assert replayed.json()["code"] == "token_reuse_detected"

        # The attacker's branch is dead — and so is the victim's, which is the correct
        # outcome: the victim re-authenticates, the attacker cannot.
        after = await client.post("/api/v1/auth/refresh", json={"refresh_token": rotated})
        assert after.status_code == 401

    async def test_reuse_is_recorded_in_the_audit_log(
        self, client: httpx.AsyncClient, container: Container
    ) -> None:
        tenant = await register_tenant(client)
        original = await _login(client, tenant)
        await client.post("/api/v1/auth/refresh", json={"refresh_token": original})
        client.cookies.clear()
        await _age_rotation(container, tenant)
        await client.post("/api/v1/auth/refresh", json={"refresh_token": original})

        audit = await client.get(
            "/api/v1/audit-events",
            headers=tenant.headers,
            params={"action": "security.token_reuse"},
        )
        assert audit.status_code == 200
        entries = audit.json()["items"]
        assert entries, "reuse detection must leave an audit trail"
        assert entries[0]["outcome"] == "DENIED"
        assert entries[0]["metadata"]["sessions_revoked"] >= 1

    async def test_grace_window_tolerates_a_concurrent_refresh(
        self, client: httpx.AsyncClient
    ) -> None:
        # Two browser tabs refreshing at the same instant present the same token. Treating
        # that as theft would sign people out constantly.
        tenant = await register_tenant(client)
        original = await _login(client, tenant)

        first = await client.post("/api/v1/auth/refresh", json={"refresh_token": original})
        assert first.status_code == 200
        client.cookies.clear()

        second = await client.post("/api/v1/auth/refresh", json={"refresh_token": original})
        assert second.status_code == 200
        assert second.json()["access_token"]

    async def test_rotation_does_not_extend_the_absolute_lifetime(
        self, client: httpx.AsyncClient, container: Container
    ) -> None:
        tenant = await register_tenant(client)
        token = await _login(client, tenant)
        from aegis_api.infrastructure.security import OpaqueTokenGenerator

        generator = OpaqueTokenGenerator()
        async with container.unit_of_work() as uow:
            before = await uow.sessions.get_by_token_hash(generator.hash(token))
        assert before is not None

        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        rotated = client.cookies.get("aegis_refresh")
        client.cookies.clear()
        assert response.status_code == 200

        async with container.unit_of_work() as uow:
            after = await uow.sessions.get_by_token_hash(generator.hash(str(rotated)))
        assert after is not None
        # A refreshed token inherits the family's expiry; otherwise a stolen token could be
        # kept alive indefinitely by refreshing it.
        assert after.expires_at == before.expires_at
        assert after.family_id == before.family_id


class TestAudienceSeparation:
    async def test_agent_token_is_rejected_on_user_routes(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        key = await client.post(
            "/api/v1/api-keys",
            headers=tenant.headers,
            json={"name": "k", "permissions": ["agent:write"], "expires_in_days": 30},
        )
        from uuid import uuid4

        registered = await client.post(
            "/api/v1/agents/register",
            headers={"Authorization": f"Bearer {key.json()['secret']}"},
            json={
                "application_name": "Audience App",
                "environment": "QA",
                "language": "JAVA",
                "fingerprint": f"fp-{uuid4().hex}",
                "hostname": "h",
                "agent_version": "0.4.0",
                "runtime_version": "21",
            },
        )
        agent_headers = {"Authorization": f"Bearer {registered.json()['agent_token']}"}

        for path in ("/api/v1/auth/me", "/api/v1/applications", "/api/v1/audit-events"):
            assert (await client.get(path, headers=agent_headers)).status_code == 401

    async def test_user_token_is_rejected_on_agent_routes(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        assert (
            await client.get("/api/v1/agents/config", headers=tenant.headers)
        ).status_code == 401
        assert (
            await client.post("/api/v1/agents/heartbeat", headers=tenant.headers, json={})
        ).status_code == 401

    async def test_mfa_challenge_token_is_not_an_access_token(
        self, client: httpx.AsyncClient
    ) -> None:
        import pyotp

        tenant = await register_tenant(client)
        enrol = await client.post(
            "/api/v1/auth/mfa/enroll", headers=tenant.headers, json={"password": tenant.password}
        )
        await client.post(
            "/api/v1/auth/mfa/confirm",
            headers=tenant.headers,
            json={"code": pyotp.TOTP(enrol.json()["secret"]).now()},
        )
        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        challenge = login.json()["challenge_token"]
        response = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {challenge}"}
        )
        assert response.status_code == 401
        client.cookies.clear()


class TestRevocationTakesEffectImmediately:
    async def test_removing_a_member_kills_their_live_session(
        self, client: httpx.AsyncClient
    ) -> None:
        from tests.conftest import role_id_for
        from tests.security.test_authorization import _member_session_with_role

        tenant = await register_tenant(client)
        viewer_role = await role_id_for(client, tenant, "Viewer")
        member = await _member_session_with_role(client, tenant, viewer_role)
        assert (await client.get("/api/v1/auth/me", headers=member)).status_code == 200

        members = await client.get("/api/v1/organizations/current/members", headers=tenant.headers)
        target = next(m for m in members.json()["items"] if m["user_id"] != tenant.user_id)
        removed = await client.delete(
            f"/api/v1/organizations/current/members/{target['membership_id']}",
            headers=tenant.headers,
        )
        assert removed.status_code == 204

        # Not "at the next token expiry" — now.
        assert (await client.get("/api/v1/auth/me", headers=member)).status_code == 401

    async def test_role_change_applies_without_waiting_for_token_expiry(
        self, client: httpx.AsyncClient
    ) -> None:
        from tests.conftest import role_id_for
        from tests.security.test_authorization import _member_session_with_role

        tenant = await register_tenant(client)
        developer = await role_id_for(client, tenant, "Developer")
        viewer = await role_id_for(client, tenant, "Viewer")
        member = await _member_session_with_role(client, tenant, developer)

        created = await client.post(
            "/api/v1/applications",
            headers=member,
            json={"name": "Before Demotion", "language": "GO"},
        )
        assert created.status_code == 201

        members = await client.get("/api/v1/organizations/current/members", headers=tenant.headers)
        target = next(m for m in members.json()["items"] if m["user_id"] != tenant.user_id)
        await client.patch(
            f"/api/v1/organizations/current/members/{target['membership_id']}",
            headers=tenant.headers,
            json={"role_ids": [viewer]},
        )

        # Permissions are re-resolved from the database on every request, so the demotion
        # bites immediately rather than at the 15-minute token boundary.
        after = await client.post(
            "/api/v1/applications",
            headers=member,
            json={"name": "After Demotion", "language": "GO"},
        )
        assert after.status_code == 403


async def _age_rotation(container: Container, tenant: Tenant) -> None:
    """Push every rotated session's timestamp outside the grace window."""
    from sqlalchemy import text

    async with container.unit_of_work() as uow:
        await uow.session.execute(
            text(
                "UPDATE sessions SET rotated_at = rotated_at - interval '1 hour' "
                "WHERE organization_id = :org AND rotated_at IS NOT NULL"
            ),
            {"org": tenant.organization_id},
        )
        await uow.commit()
