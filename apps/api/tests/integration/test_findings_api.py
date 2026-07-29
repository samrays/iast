"""The findings API: the queue, the evidence, and who is allowed to dismiss a vulnerability."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest
from tests.conftest import Tenant
from tests.integration.test_findings_pipeline import register_agent, taint_hit

from aegis_api.application.findings import ProcessRuntimeEvents
from aegis_api.container import Container

pytestmark = [pytest.mark.integration]


async def seed_finding(
    client: httpx.AsyncClient, container: Container, tenant: Tenant, **overrides: Any
) -> dict[str, Any]:
    """Drive one event through the real pipeline, then read it back through the API."""
    agent_id, _ = await register_agent(client, container, tenant)
    await ProcessRuntimeEvents(uow_factory=container.unit_of_work).execute(
        [taint_hit(organization_id=tenant.organization_id, agent_id=agent_id, **overrides)]
    )
    listed = await client.get("/api/v1/findings", headers=tenant.headers)
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    assert items, "the pipeline produced no finding"
    return items[0]


class TestQueue:
    async def test_a_finding_the_agent_reported_is_visible_to_a_person(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)

        # The whole point of the phase: a vulnerability found in a running application, in
        # front of a human, with enough context to act.
        assert finding["title"].startswith("SQL injection in UserRepository")
        assert finding["severity"] == "CRITICAL"
        assert finding["status"] == "OPEN"
        assert finding["cwe_id"] == 89
        assert finding["risk_score"] > 0
        assert finding["environments_seen"] == ["PRODUCTION"]

    async def test_the_score_arrives_with_its_reasoning(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)
        factors = {f["name"] for f in finding["risk_factors"]}
        # A number a developer cannot interrogate is a number they argue with.
        assert {"severity", "confidence", "exposure"} <= factors
        assert all(f["reason"] for f in finding["risk_factors"])

    async def test_detail_carries_the_evidence_needed_to_reproduce_it(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        listed = await seed_finding(client, container, tenant)
        response = await client.get(f"/api/v1/findings/{listed['id']}", headers=tenant.headers)
        assert response.status_code == 200
        detail = response.json()

        occurrence = detail["occurrences"][0]
        assert occurrence["sink_argument"].startswith("SELECT name FROM users")
        assert occurrence["tainted_ranges"][0] == {
            "start": 37,
            "length": 10,
            "source": "SOURCE_KIND_PARAMETER",
            "source_name": "name",
        }
        assert any(frame["application_code"] for frame in occurrence["stack_frames"])

    async def test_filters_narrow_the_queue(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        await seed_finding(client, container, tenant)

        matching = await client.get(
            "/api/v1/findings?status=OPEN&severity=CRITICAL&rule_key=sql-injection",
            headers=tenant.headers,
        )
        assert matching.json()["items"]

        missing = await client.get("/api/v1/findings?status=REMEDIATED", headers=tenant.headers)
        assert missing.json()["items"] == []

    async def test_an_unknown_finding_is_a_404_not_a_500(
        self, client: httpx.AsyncClient, tenant: Tenant
    ) -> None:
        response = await client.get(f"/api/v1/findings/{uuid4()}", headers=tenant.headers)
        assert response.status_code == 404


class TestTriage:
    async def test_a_status_change_is_recorded_in_the_thread_and_the_audit_log(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)

        response = await client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=tenant.headers,
            json={"status": "CONFIRMED", "note": "Reproduced on staging."},
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "CONFIRMED"

        detail = (
            await client.get(f"/api/v1/findings/{finding['id']}", headers=tenant.headers)
        ).json()
        assert detail["comments"][-1]["status_to"] == "CONFIRMED"
        assert detail["comments"][-1]["body"] == "Reproduced on staging."

        # The audit log answers "who changed what"; the comment thread answers "why".
        audit = await client.get(
            "/api/v1/audit-events?action=finding.triaged", headers=tenant.headers
        )
        assert audit.json()["items"], audit.text

    async def test_an_illegal_transition_is_refused(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)
        await client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=tenant.headers,
            json={"status": "REMEDIATED"},
        )
        response = await client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=tenant.headers,
            json={"status": "FALSE_POSITIVE", "note": "changed my mind"},
        )
        # A triage history that cannot be trusted is worse than none.
        assert response.status_code == 409, response.text

    async def test_suppressing_without_a_reason_is_refused(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)
        response = await client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=tenant.headers,
            json={"status": "ACCEPTED_RISK"},
        )
        # Someone will read this in six months wondering why a live vulnerability is accepted.
        assert response.status_code == 409

    async def test_accepted_risk_gets_an_expiry(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)
        response = await client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=tenant.headers,
            json={
                "status": "ACCEPTED_RISK",
                "note": "Mitigated by the edge WAF rule.",
                "accepted_for_days": 30,
            },
        )
        assert response.status_code == 200
        # A risk accepted once, forever, silently is how a finding becomes an incident.
        assert response.json()["accepted_until"] is not None

    async def test_a_comment_can_be_added_without_changing_state(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        finding = await seed_finding(client, container, tenant)
        response = await client.post(
            f"/api/v1/findings/{finding['id']}/comments",
            headers=tenant.headers,
            json={"body": "Owned by the payments team; ticket PAY-421."},
        )
        assert response.status_code == 201
        assert response.json()["status_to"] is None


class TestIsolation:
    async def test_one_tenant_cannot_read_another_tenants_finding(
        self,
        client: httpx.AsyncClient,
        container: Container,
        tenant: Tenant,
        other_tenant: Tenant,
    ) -> None:
        finding = await seed_finding(client, container, tenant)

        response = await client.get(
            f"/api/v1/findings/{finding['id']}", headers=other_tenant.headers
        )
        # 404 rather than 403: confirming the id exists would itself leak that another tenant
        # has a finding by that identifier.
        assert response.status_code == 404

    async def test_one_tenant_cannot_triage_another_tenants_finding(
        self,
        client: httpx.AsyncClient,
        container: Container,
        tenant: Tenant,
        other_tenant: Tenant,
    ) -> None:
        finding = await seed_finding(client, container, tenant)
        response = await client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=other_tenant.headers,
            json={"status": "FALSE_POSITIVE", "note": "not mine to dismiss"},
        )
        assert response.status_code == 404

    async def test_reading_findings_requires_authentication(
        self, client: httpx.AsyncClient
    ) -> None:
        assert (await client.get("/api/v1/findings")).status_code == 401
