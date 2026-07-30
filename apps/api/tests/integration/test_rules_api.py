"""The rule catalogue over HTTP: what a tenant sees, and what they may switch off."""

from __future__ import annotations

import httpx
import pytest
from tests.conftest import Tenant

pytestmark = [pytest.mark.integration]


class TestCatalogue:
    async def test_ships_with_every_rule_on(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.get("/api/v1/rules", headers=tenant.headers)
        assert response.status_code == 200
        rules = response.json()

        # A catalogue that arrived empty, or off, would report nothing on day one — and a
        # clean report is the most dangerous output this product has.
        assert len(rules) == 11
        assert all(rule["enabled"] for rule in rules)

    async def test_is_ordered_worst_first(self, client: httpx.AsyncClient, tenant: Tenant) -> None:
        rules = (await client.get("/api/v1/rules", headers=tenant.headers)).json()
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [order[rule["severity"]] for rule in rules]
        assert ranks == sorted(ranks)

    async def test_every_rule_explains_itself(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        for rule in (await client.get("/api/v1/rules", headers=tenant.headers)).json():
            assert rule["title"]
            assert rule["description"]
            assert rule["cwe_id"]


class TestToggling:
    async def test_disabling_requires_a_reason(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.put(
            "/api/v1/rules/log-injection",
            headers=tenant.headers,
            json={"enabled": False},
        )
        # Somebody will find this switched off months later and need to know whether it
        # still should be.
        assert response.status_code == 409, response.text

    async def test_a_disabled_rule_stays_disabled(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        disabled = await client.put(
            "/api/v1/rules/log-injection",
            headers=tenant.headers,
            json={"enabled": False, "reason": "Logs are structured; newlines cannot forge a line."},
        )
        assert disabled.status_code == 200
        assert disabled.json()["enabled"] is False

        rules = {
            r["key"]: r for r in (await client.get("/api/v1/rules", headers=tenant.headers)).json()
        }
        assert rules["log-injection"]["enabled"] is False
        assert "structured" in rules["log-injection"]["disabled_reason"]
        # Everything else is untouched.
        assert rules["sql-injection"]["enabled"] is True

    async def test_re_enabling_clears_the_reason(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        await client.put(
            "/api/v1/rules/ssrf",
            headers=tenant.headers,
            json={"enabled": False, "reason": "Egress is blocked at the network layer."},
        )
        response = await client.put(
            "/api/v1/rules/ssrf", headers=tenant.headers, json={"enabled": True}
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is True
        assert response.json()["disabled_reason"] == ""

    async def test_an_unknown_rule_is_refused(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.put(
            "/api/v1/rules/not-a-real-rule",
            headers=tenant.headers,
            json={"enabled": False, "reason": "x"},
        )
        # Storing it would let the settings row accumulate opt-outs for rules that do not
        # exist, which reads later as though detection were off when it never was.
        assert response.status_code == 404

    async def test_switching_detection_off_is_audited(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        await client.put(
            "/api/v1/rules/xpath-injection",
            headers=tenant.headers,
            json={"enabled": False, "reason": "No XML parsing in this service."},
        )
        audit = await client.get("/api/v1/audit-events?action=rule.toggled", headers=tenant.headers)
        entries = audit.json()["items"]
        # This is what an attacker with a stolen console session does first, and what somebody
        # will have to account for later.
        assert entries, audit.text
        assert entries[0]["resource_id"] == "xpath-injection"
        assert entries[0]["metadata"]["enabled"] is False


class TestIsolation:
    async def test_one_tenants_opt_out_does_not_reach_another(
        self, client: httpx.AsyncClient, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        await client.put(
            "/api/v1/rules/open-redirect",
            headers=tenant.headers,
            json={"enabled": False, "reason": "Redirects are allow-listed upstream."},
        )

        theirs = {
            r["key"]: r
            for r in (await client.get("/api/v1/rules", headers=other_tenant.headers)).json()
        }
        # A customer's decision about their own detection must not weaken anybody else's.
        assert theirs["open-redirect"]["enabled"] is True

    async def test_reading_the_catalogue_requires_authentication(
        self, client: httpx.AsyncClient
    ) -> None:
        assert (await client.get("/api/v1/rules")).status_code == 401
