"""The worker pipeline, against a real database.

The events here are the shape the Java agent actually emits — the same NDJSON the gateway
writes to its sink — rather than a convenient invention. A pipeline tested against its own
idea of the wire format is a pipeline that breaks the first time it meets an agent.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from tests.conftest import Tenant, create_application

from aegis_api.application.findings import ProcessRuntimeEvents
from aegis_api.container import Container
from aegis_api.domain.entities.findings import Confidence, FindingStatus, Severity

pytestmark = [pytest.mark.integration]

NOW_MS = int(datetime(2026, 7, 29, 12, 0, tzinfo=UTC).timestamp() * 1000)


def taint_hit(
    *,
    organization_id: str,
    agent_id: str,
    rule_key: str = "sql-injection",
    severity: str = "SEVERITY_CRITICAL",
    confidence: str = "CONFIDENCE_EXPLOITED",
    sink: str = "java.sql.Statement#execute(String)",
    method: str = "findByNameUnsafe",
    route: str = "/users/search",
    occurred_at_ms: int = NOW_MS,
    event_id: str | None = None,
) -> dict[str, Any]:
    """One event in exactly the envelope the gateway writes."""
    return {
        "organization_id": organization_id,
        "agent_id": agent_id,
        "environment_id": "",
        "event_id": event_id or uuid4().hex,
        "type": "EVENT_TYPE_TAINT_HIT",
        "occurred_at_ms": occurred_at_ms,
        "monotonic_nanos": 1,
        "trace_id": uuid4().hex,
        "replayed": False,
        "payload": {
            "rule_key": rule_key,
            "severity": severity,
            "confidence": confidence,
            "sink_signature": sink,
            "sink_argument": "SELECT name FROM users WHERE name = '' OR 1=1--'",
            "stack_fingerprint": "ignored-by-the-worker",
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
                    "method_name": method,
                    "line_number": 42,
                    "application_code": True,
                },
                {
                    "declaring_class": "org.eclipse.jetty.server.Handler",
                    "method_name": "handle",
                    "line_number": 900,
                    "application_code": False,
                },
            ],
            "sanitizers_applied": [],
            "request": {
                "method": "GET",
                "path": route,
                "route_template": route,
                "remote_addr": "203.0.113.7",
                "parameters": {"name": "' OR 1=1--"},
                "headers": {},
                "body_excerpt": "",
            },
        },
    }


async def register_agent(client: Any, container: Container, tenant: Tenant) -> tuple[str, UUID]:
    """Register an application with a production environment and an agent reporting into it."""
    application = await create_application(client, tenant, name=f"svc-{uuid4().hex[:8]}")

    response = await client.post(
        "/api/v1/agents/register",
        headers=tenant.headers,
        json={
            "application_name": application["name"],
            "environment": "PRODUCTION",
            "fingerprint": uuid4().hex,
            "hostname": "pod-1",
            "agent_version": "0.4.0",
            "runtime_version": "21.0.1",
            "language": "JAVA",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["agent"]["id"], UUID(application["id"])


class TestIngest:
    async def test_one_event_becomes_one_finding(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, application_id = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

        result = await pipeline.execute(
            [taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)]
        )

        assert result.findings_created == 1
        assert result.occurrences_stored == 1

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(UUID(tenant.organization_id))
            finding = await _one_finding(uow)
            assert finding.application_id == application_id

    async def test_the_same_defect_seen_a_thousand_times_is_one_finding(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

        events = [
            taint_hit(organization_id=tenant.organization_id, agent_id=agent_id) for _ in range(50)
        ]
        result = await pipeline.execute(events)

        # The collapse that makes this a security product rather than a log.
        assert result.findings_created == 1
        assert result.findings_updated == 49

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(UUID(tenant.organization_id))
            row = await _one_finding(uow)
            assert row.occurrence_count == 50
            # Evidence is rate-limited: 50 near-identical traces are not 50 times as useful.
            assert result.occurrences_stored == 1

    async def test_replaying_the_stream_does_not_duplicate_anything(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)
        events = [taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)]

        await pipeline.execute(events)
        second = await pipeline.execute(events)

        # The agent's transport is at-least-once and its spool replays after an outage, so
        # this is the normal case rather than an edge case.
        assert second.findings_created == 0
        assert second.findings_updated == 1

    async def test_different_methods_are_different_findings(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

        result = await pipeline.execute(
            [
                taint_hit(
                    organization_id=tenant.organization_id, agent_id=agent_id, method="findByName"
                ),
                taint_hit(
                    organization_id=tenant.organization_id, agent_id=agent_id, method="searchAll"
                ),
            ]
        )

        # Two call paths to the same sink are two defects: fixing one line does not fix both.
        assert result.findings_created == 2

    async def test_the_finding_carries_evidence_a_developer_can_act_on(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, application_id = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)
        await pipeline.execute(
            [taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)]
        )

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(UUID(tenant.organization_id))
            finding = await _one_finding(uow)

            assert finding.title == "SQL injection in UserRepository.findByNameUnsafe"
            assert finding.cwe_id == 89
            assert finding.application_id == application_id
            assert finding.severity is Severity.CRITICAL
            assert finding.confidence is Confidence.EXPLOITED
            assert finding.status is FindingStatus.OPEN
            assert finding.environments_seen == ("PRODUCTION",)
            assert finding.route_templates == ("/users/search",)
            # Scored, and the score explains itself.
            assert finding.risk_score > 0
            assert {name for name, _, _ in finding.risk_factors} >= {"severity", "exposure"}

            occurrences = await uow.findings.list_occurrences(finding.id)
            assert len(occurrences) == 1
            assert occurrences[0].tainted_ranges == ((37, 10, "SOURCE_KIND_PARAMETER", "name"),)
            assert occurrences[0].attack_detected

    async def test_a_second_evidence_sample_is_kept_once_the_interval_passes(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(
            uow_factory=container.unit_of_work, evidence_interval=timedelta(minutes=30)
        )

        await pipeline.execute(
            [taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)]
        )
        later = await pipeline.execute(
            [
                taint_hit(
                    organization_id=tenant.organization_id,
                    agent_id=agent_id,
                    occurred_at_ms=NOW_MS + 60 * 60 * 1000,
                )
            ]
        )
        assert later.occurrences_stored == 1


class TestAttribution:
    async def test_an_unregistered_agent_is_rejected(
        self, container: Container, tenant: Tenant
    ) -> None:
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

        result = await pipeline.execute(
            [taint_hit(organization_id=tenant.organization_id, agent_id=str(uuid4()))]
        )

        # Accepting would let anything holding a token invent an application to file findings
        # against.
        assert result.findings_created == 0
        assert result.rejected == 1

    async def test_an_event_with_no_agent_is_rejected(
        self, container: Container, tenant: Tenant
    ) -> None:
        event = taint_hit(organization_id=tenant.organization_id, agent_id="x")
        event["agent_id"] = ""
        result = await ProcessRuntimeEvents(uow_factory=container.unit_of_work).execute([event])
        assert result.rejected == 1

    async def test_an_agent_from_another_tenant_cannot_be_resolved(
        self, client, container: Container, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

        # The agent exists — but not for this tenant. Row-level security and the repository's
        # own predicate both have to hold for this to come back empty.
        result = await pipeline.execute(
            [taint_hit(organization_id=other_tenant.organization_id, agent_id=agent_id)]
        )
        assert result.rejected == 1
        assert result.findings_created == 0


class TestMalformedInput:
    @pytest.mark.parametrize(
        "mutate,expected",
        [
            (lambda e: e.update(organization_id="not-a-uuid"), "rejected"),
            (lambda e: e["payload"].pop("sink_signature"), "rejected"),
            (lambda e: e["payload"].update(rule_key="made-up-rule"), "rejected"),
            (lambda e: e.update(type="EVENT_TYPE_ROUTE"), "ignored"),
        ],
    )
    async def test_bad_events_are_dropped_not_retried_forever(
        self, client, container: Container, tenant: Tenant, mutate: Any, expected: str
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        event = taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)
        mutate(event)

        result = await ProcessRuntimeEvents(uow_factory=container.unit_of_work).execute([event])

        # A malformed event retried forever blocks the stream behind it, and a stalled worker
        # is indistinguishable from an application with no vulnerabilities.
        assert getattr(result, expected) == 1
        assert result.findings_created == 0

    async def test_one_bad_event_does_not_stop_the_batch(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        good = taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)
        bad = taint_hit(organization_id=tenant.organization_id, agent_id=agent_id)
        bad["payload"]["rule_key"] = "nonsense"

        result = await ProcessRuntimeEvents(uow_factory=container.unit_of_work).execute([bad, good])

        assert result.rejected == 1
        assert result.findings_created == 1


class TestScoring:
    async def test_confidence_is_raised_by_a_later_event_but_never_lowered(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        agent_id, _ = await register_agent(client, container, tenant)
        pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)

        await pipeline.execute(
            [
                taint_hit(
                    organization_id=tenant.organization_id,
                    agent_id=agent_id,
                    confidence="CONFIDENCE_EXPLOITED",
                )
            ]
        )
        await pipeline.execute(
            [
                taint_hit(
                    organization_id=tenant.organization_id,
                    agent_id=agent_id,
                    confidence="CONFIDENCE_SUSPECTED",
                )
            ]
        )

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(UUID(tenant.organization_id))
            finding = await _one_finding(uow)
            # Losing a confirmation because one request took a less complete path would make
            # the queue flap between severities for the same unchanged defect.
            assert finding.confidence is Confidence.EXPLOITED


async def _one_finding(uow: Any) -> Any:
    """The single finding belonging to this test's tenant."""
    from sqlalchemy import select

    from aegis_api.infrastructure.db import mappers as m
    from aegis_api.infrastructure.db.models import FindingRecord

    records = (
        (await uow.session.execute(select(FindingRecord).order_by(FindingRecord.created_at.desc())))
        .scalars()
        .all()
    )
    assert records, "no finding was written"
    return m.finding_to_domain(records[0])


class TestStreamOperation:
    """The CLI entry point, reading the NDJSON the gateway actually writes."""

    async def test_processes_a_captured_stream_file(
        self, client, container: Container, tenant: Tenant, tmp_path: Any
    ) -> None:
        import json

        from aegis_api import operations

        agent_id, _ = await register_agent(client, container, tenant)
        stream = tmp_path / "events.ndjson"
        stream.write_text(
            "\n".join(
                json.dumps(taint_hit(organization_id=tenant.organization_id, agent_id=agent_id))
                for _ in range(3)
            )
            # A blank line and a truncated one: a capture interrupted mid-write is a normal
            # way for a file to end, not a reason to process none of it.
            + '\n\n{"broken"\n',
            encoding="utf-8",
        )

        result = await operations.process_runtime_events(
            container, source=f"file:{stream}", batch_size=2
        )

        assert result.findings_created == 1
        assert result.findings_updated == 2
        assert result.rejected == 1

    async def test_a_missing_stream_is_an_error_not_a_silent_success(
        self, container: Container, tmp_path: Any
    ) -> None:
        from aegis_api import operations

        with pytest.raises(FileNotFoundError):
            await operations.process_runtime_events(
                container, source=f"file:{tmp_path / 'absent.ndjson'}"
            )
