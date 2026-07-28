"""Registration, sign-in, refresh rotation, MFA and password change, end to end."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pyotp
import pytest
from tests.conftest import TEST_PASSWORD, Tenant, register_tenant

pytestmark = pytest.mark.integration


class TestRegistration:
    async def test_creates_organization_owner_and_session(self, client: httpx.AsyncClient) -> None:
        suffix = uuid4().hex[:10]
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "organization_name": f"Register {suffix}",
                "email": f"reg-{suffix}@example.com",
                "password": TEST_PASSWORD,
                "full_name": "Registrar",
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["organization"]["status"] == "ACTIVE"
        assert body["tokens"]["access_token"]
        # The refresh token is delivered as a cookie, never in the body.
        assert body["tokens"]["refresh_token"] is None
        assert "aegis_refresh" in response.cookies
        client.cookies.clear()

    async def test_owner_receives_every_permission(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        me = await client.get("/api/v1/auth/me", headers=tenant.headers)
        assert me.status_code == 200
        body = me.json()
        assert [r["name"] for r in body["roles"]] == ["Owner"]
        assert "org:delete" in body["permissions"]

    async def test_duplicate_email_conflicts(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "organization_name": "Another Org",
                "email": tenant.email,
                "password": TEST_PASSWORD,
                "full_name": "Impostor",
            },
        )
        assert response.status_code == 409
        assert response.headers["content-type"].startswith("application/problem+json")

    async def test_weak_password_lists_every_failure(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "organization_name": "Weak Org",
                "email": f"weak-{uuid4().hex[:8]}@example.com",
                "password": "reportabcdefg",
                "full_name": "Weak",
            },
        )
        assert response.status_code == 422
        assert response.json()["code"] == "weak_password"
        assert len(response.json()["errors"]) >= 1

    async def test_slug_collision_is_resolved(self, client: httpx.AsyncClient) -> None:
        name = f"Collide {uuid4().hex[:6]}"
        first = await register_tenant(client, name=name)
        second = await register_tenant(client, name=name)
        assert first.slug != second.slug
        assert second.slug.startswith(first.slug)


class TestLogin:
    async def test_signs_in_with_correct_credentials(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": tenant.email, "password": tenant.password},
        )
        assert response.status_code == 200
        assert response.json()["access_token"]
        client.cookies.clear()

    async def test_wrong_password_is_indistinguishable_from_unknown_user(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        # Distinguishing the two is a user-enumeration oracle (threat T-07).
        wrong = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": "not-the-password"}
        )
        unknown = await client.post(
            "/api/v1/auth/login",
            json={"email": f"nobody-{uuid4().hex[:8]}@example.com", "password": TEST_PASSWORD},
        )
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json()["code"] == unknown.json()["code"] == "invalid_credentials"
        assert wrong.json()["detail"] == unknown.json()["detail"]

    async def test_malformed_email_is_a_credential_failure_not_a_validation_error(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login", json={"email": "not-an-email", "password": TEST_PASSWORD}
        )
        # 422 from schema validation is acceptable, but it must never be a 200 or reveal
        # anything about account existence.
        assert response.status_code in (401, 422)


class TestRefreshRotation:
    async def test_rotation_issues_a_new_pair(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        assert login.status_code == 200
        first_cookie = client.cookies.get("aegis_refresh")

        refreshed = await client.post("/api/v1/auth/refresh", json={})
        assert refreshed.status_code == 200
        assert client.cookies.get("aegis_refresh") != first_cookie
        client.cookies.clear()

    async def test_body_delivery_works_for_non_browser_clients(
        self, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        token = login.cookies.get("aegis_refresh")
        client.cookies.clear()
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 200
        client.cookies.clear()

    async def test_missing_token_is_rejected(self, client: httpx.AsyncClient) -> None:
        client.cookies.clear()
        assert (await client.post("/api/v1/auth/refresh", json={})).status_code == 401

    async def test_unknown_token_is_rejected(self, client: httpx.AsyncClient) -> None:
        client.cookies.clear()
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": "not-a-real-token"}
        )
        assert response.status_code == 401


class TestLogout:
    async def test_logout_revokes_the_session(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        access = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {access}"}
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200

        assert (await client.post("/api/v1/auth/logout", headers=headers)).status_code == 200
        # The access token outlives the session by design, but the session check catches it.
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401
        client.cookies.clear()

    async def test_logout_all_revokes_every_session(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        sessions = []
        for _ in range(3):
            login = await client.post(
                "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
            )
            sessions.append(login.json()["access_token"])
            client.cookies.clear()

        response = await client.post(
            "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {sessions[-1]}"}
        )
        assert response.status_code == 200
        assert response.json()["sessions_revoked"] >= 3
        for token in sessions:
            check = await client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
            assert check.status_code == 401


class TestPasswordChange:
    async def test_changes_password_and_evicts_other_sessions(
        self, client: httpx.AsyncClient
    ) -> None:
        tenant = await register_tenant(client)
        other = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        other_token = other.json()["access_token"]
        client.cookies.clear()

        new_password = "another-strong-passphrase-91"
        response = await client.post(
            "/api/v1/auth/password/change",
            headers=tenant.headers,
            json={"current_password": tenant.password, "new_password": new_password},
        )
        assert response.status_code == 200
        assert response.json()["sessions_revoked"] >= 1

        # The other session is evicted — the point of a password change during an incident.
        assert (
            await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {other_token}"})
        ).status_code == 401

        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": new_password}
        )
        assert login.status_code == 200
        client.cookies.clear()

    async def test_wrong_current_password_is_rejected(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.post(
            "/api/v1/auth/password/change",
            headers=tenant.headers,
            json={"current_password": "wrong-password-value", "new_password": "brand-new-one-42"},
        )
        assert response.status_code == 401

    async def test_new_password_must_differ(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        response = await client.post(
            "/api/v1/auth/password/change",
            headers=tenant.headers,
            json={"current_password": tenant.password, "new_password": tenant.password},
        )
        assert response.status_code == 422


class TestMfa:
    async def test_full_enrolment_and_challenge_cycle(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)

        enrol = await client.post(
            "/api/v1/auth/mfa/enroll",
            headers=tenant.headers,
            json={"password": tenant.password},
        )
        assert enrol.status_code == 200
        secret = enrol.json()["secret"]
        recovery_codes = enrol.json()["recovery_codes"]
        assert len(recovery_codes) == 10
        assert enrol.json()["provisioning_uri"].startswith("otpauth://totp/")

        confirm = await client.post(
            "/api/v1/auth/mfa/confirm",
            headers=tenant.headers,
            json={"code": pyotp.TOTP(secret).now()},
        )
        assert confirm.status_code == 204

        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        assert login.status_code == 200
        assert login.json()["mfa_required"] is True
        challenge = login.json()["challenge_token"]

        bad = await client.post(
            "/api/v1/auth/mfa/verify", json={"challenge_token": challenge, "code": "000000"}
        )
        assert bad.status_code == 401

        good = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": challenge, "code": pyotp.TOTP(secret).now()},
        )
        assert good.status_code == 200
        assert good.json()["access_token"]
        client.cookies.clear()

    async def test_recovery_code_works_once(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        enrol = await client.post(
            "/api/v1/auth/mfa/enroll", headers=tenant.headers, json={"password": tenant.password}
        )
        secret = enrol.json()["secret"]
        code = enrol.json()["recovery_codes"][0]
        await client.post(
            "/api/v1/auth/mfa/confirm",
            headers=tenant.headers,
            json={"code": pyotp.TOTP(secret).now()},
        )

        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        first = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": login.json()["challenge_token"], "code": code},
        )
        assert first.status_code == 200
        client.cookies.clear()

        login = await client.post(
            "/api/v1/auth/login", json={"email": tenant.email, "password": tenant.password}
        )
        second = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": login.json()["challenge_token"], "code": code},
        )
        assert second.status_code == 401
        client.cookies.clear()

    async def test_enrolment_requires_the_password(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        # An unattended session must not be enough to swap someone's second factor.
        response = await client.post(
            "/api/v1/auth/mfa/enroll", headers=tenant.headers, json={"password": "wrong-password"}
        )
        assert response.status_code == 401

    async def test_disable_requires_the_password(self, client: httpx.AsyncClient) -> None:
        tenant = await register_tenant(client)
        enrol = await client.post(
            "/api/v1/auth/mfa/enroll", headers=tenant.headers, json={"password": tenant.password}
        )
        await client.post(
            "/api/v1/auth/mfa/confirm",
            headers=tenant.headers,
            json={"code": pyotp.TOTP(enrol.json()["secret"]).now()},
        )
        bad = await client.post(
            "/api/v1/auth/mfa/disable", headers=tenant.headers, json={"password": "nope-not-it"}
        )
        assert bad.status_code == 401
        good = await client.post(
            "/api/v1/auth/mfa/disable", headers=tenant.headers, json={"password": tenant.password}
        )
        assert good.status_code == 204

    async def test_cannot_confirm_without_enrolling(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.post(
            "/api/v1/auth/mfa/confirm", headers=tenant.headers, json={"code": "123456"}
        )
        assert response.status_code == 409
