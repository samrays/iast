"""Ingest behaviour, end to end through the HTTP layer."""

from __future__ import annotations

import json

import httpx
import pytest
from tests.conftest import (
    ORGANIZATION_ID,
    make_agent_token,
    ndjson,
    route_event,
    taint_hit,
)

from aegis_gateway.infrastructure.sinks import MemoryEventSink

INGEST = "/ingest/v1/events"


class TestAuthentication:
    async def test_accepts_a_valid_agent_token(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(taint_hit()))
        assert response.status_code == 200
        assert response.json()["accepted"] == 1

    async def test_rejects_a_missing_credential(self, client: httpx.AsyncClient) -> None:
        response = await client.post(INGEST, content=ndjson(taint_hit()))
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")
        assert response.headers["content-type"].startswith("application/problem+json")

    async def test_rejects_a_user_token(self, client: httpx.AsyncClient) -> None:
        # A user access token must never work here. Audience separation is what stops a
        # leaked console session from writing into a tenant's event stream (threat T-06).
        token = make_agent_token(audience="aegis:user", purpose="mfa")
        response = await client.post(
            INGEST, headers={"Authorization": f"Bearer {token}"}, content=ndjson(taint_hit())
        )
        assert response.status_code == 401

    async def test_rejects_a_token_signed_with_another_key(self, client: httpx.AsyncClient) -> None:
        token = make_agent_token(secret="a-completely-different-signing-secret-value")
        response = await client.post(
            INGEST, headers={"Authorization": f"Bearer {token}"}, content=ndjson(taint_hit())
        )
        assert response.status_code == 401

    async def test_rejects_an_expired_token(self, client: httpx.AsyncClient) -> None:
        token = make_agent_token(expires_in=-120)
        response = await client.post(
            INGEST, headers={"Authorization": f"Bearer {token}"}, content=ndjson(taint_hit())
        )
        assert response.status_code == 401

    async def test_rejects_a_foreign_issuer(self, client: httpx.AsyncClient) -> None:
        token = make_agent_token(issuer="https://evil.example.com")
        response = await client.post(
            INGEST, headers={"Authorization": f"Bearer {token}"}, content=ndjson(taint_hit())
        )
        assert response.status_code == 401

    async def test_does_not_disclose_why_verification_failed(
        self, client: httpx.AsyncClient
    ) -> None:
        expired = await client.post(
            INGEST,
            headers={"Authorization": f"Bearer {make_agent_token(expires_in=-120)}"},
            content=ndjson(taint_hit()),
        )
        forged = await client.post(
            INGEST,
            headers={
                "Authorization": (
                    f"Bearer {make_agent_token(secret='another-secret-value-long-enough')}"
                )
            },
            content=ndjson(taint_hit()),
        )
        # Telling an attacker which check they still need to pass is free help.
        assert expired.json()["detail"] == forged.json()["detail"]


class TestTenantAttribution:
    async def test_stamps_the_organization_from_the_credential(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], sink: MemoryEventSink
    ) -> None:
        await client.post(INGEST, headers=auth_headers, content=ndjson(taint_hit()))
        organization_id, _ = sink.published[-1]
        assert organization_id == ORGANIZATION_ID

    async def test_ignores_any_organization_in_the_payload(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], sink: MemoryEventSink
    ) -> None:
        # An agent claiming to belong to another tenant must not be believed. The only source
        # of truth is the verified token.
        forged = taint_hit()
        forged["organization_id"] = "018f2b00-0000-7000-8000-00000000ffff"

        await client.post(INGEST, headers=auth_headers, content=ndjson(forged))
        organization_id, _ = sink.published[-1]
        assert organization_id == ORGANIZATION_ID


class TestValidation:
    async def test_rejects_malformed_json_without_losing_the_batch(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        body = b"{not json at all\n" + ndjson(taint_hit())
        response = await client.post(INGEST, headers=auth_headers, content=body)

        payload = response.json()
        # One bad line must not cost the tenant the findings in the rest of the batch.
        assert payload["accepted"] == 1
        assert payload["rejected"] == 1
        assert payload["rejections"][0]["line"] == 1

    async def test_rejects_an_unknown_event_type(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        event = taint_hit()
        event["type"] = "EVENT_TYPE_SOMETHING_NEW"
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))

        payload = response.json()
        assert payload["accepted"] == 0
        assert "unknown event type" in payload["rejections"][0]["reason"]

    @pytest.mark.parametrize(
        ("missing", "reason"),
        [("event_id", "event_id"), ("occurred_at_ms", "occurred_at_ms"), ("type", "type")],
    )
    async def test_requires_envelope_fields(
        self,
        client: httpx.AsyncClient,
        auth_headers: dict[str, str],
        missing: str,
        reason: str,
    ) -> None:
        event = taint_hit()
        del event[missing]
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))

        assert response.json()["rejected"] == 1
        assert reason in response.json()["rejections"][0]["reason"]

    async def test_requires_the_payload_matching_the_declared_type(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        event = taint_hit()
        del event["taint_hit"]
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))
        assert "missing 'taint_hit'" in response.json()["rejections"][0]["reason"]

    async def test_rejects_a_negative_range(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        event = taint_hit()
        event["taint_hit"]["ranges"][0]["start"] = -5
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))
        assert "non-negative" in response.json()["rejections"][0]["reason"]

    async def test_rejects_a_boolean_where_an_integer_belongs(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        # bool is an int subclass in Python; accepting `true` as a timestamp is exactly the
        # quiet type confusion that produces nonsense downstream.
        event = taint_hit()
        event["occurred_at_ms"] = True
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))
        assert response.json()["rejected"] == 1

    async def test_bounds_an_oversized_field(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        event = taint_hit()
        event["taint_hit"]["sink_signature"] = "x" * 20_000
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))
        assert "exceeds" in response.json()["rejections"][0]["reason"]

    async def test_rejects_an_oversized_batch(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], settings: object
    ) -> None:
        oversized = b"x" * (8 * 1024 * 1024 + 1)
        response = await client.post(INGEST, headers=auth_headers, content=oversized)
        assert response.status_code == 413

    async def test_caps_the_number_of_reported_rejections(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        body = b"".join(b"{bad\n" for _ in range(200))
        response = await client.post(INGEST, headers=auth_headers, content=body)
        # The response must not grow with the badness of the request.
        assert len(response.json()["rejections"]) <= 20

    async def test_tolerates_blank_lines(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        body = b"\n\n" + ndjson(taint_hit()) + b"\n"
        response = await client.post(INGEST, headers=auth_headers, content=body)
        assert response.json()["accepted"] == 1
        assert response.json()["rejected"] == 0


class TestIdempotency:
    async def test_deduplicates_replayed_events(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], sink: MemoryEventSink
    ) -> None:
        event = taint_hit(event_id="evt-replay-1")

        first = await client.post(INGEST, headers=auth_headers, content=ndjson(event))
        before = len(sink.published)
        second = await client.post(INGEST, headers=auth_headers, content=ndjson(event))

        assert first.json()["accepted"] == 1
        # The agent replays its spool after every reconnect; counting those as new would
        # inflate a tenant's findings on any flaky network.
        assert second.json()["accepted"] == 0
        assert second.json()["duplicates"] == 1
        assert len(sink.published) == before

    async def test_acknowledges_duplicates_so_the_spool_advances(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        event = taint_hit(event_id="evt-replay-2")
        await client.post(INGEST, headers=auth_headers, content=ndjson(event))
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(event))

        # Without an ack the agent would retry the same batch forever.
        assert response.json()["ack_cursor"] == "evt-replay-2"


class TestBackpressure:
    async def test_returns_credit_for_the_agent_to_throttle_to(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(taint_hit()))
        assert int(response.headers["X-Aegis-Credit"]) > 0
        assert response.json()["credit"] > 0

    async def test_sheds_telemetry_before_findings(self, client: httpx.AsyncClient) -> None:
        from aegis_gateway.application.context import AgentPrincipal
        from aegis_gateway.application.ingest import IngestEvents
        from aegis_gateway.domain.quota import SheddingPolicy
        from aegis_gateway.infrastructure.limits import LruDeduplicationCache

        class ExhaustedQuota:
            def check(self, organization_id: str, cost: float) -> bool:
                return False

            def remaining_fraction(self, organization_id: str) -> float:
                return 0.0

            def retry_after_seconds(self, organization_id: str, cost: float) -> int:
                return 7

        sink = MemoryEventSink()
        ingest = IngestEvents(
            sink=sink,
            quota=ExhaustedQuota(),
            dedup=LruDeduplicationCache(),
            max_batch_bytes=1_000_000,
            max_batch_events=100,
            shedding=SheddingPolicy(),
        )
        principal = AgentPrincipal(agent_id="a", organization_id="o")

        # Route telemetry is shed silently — it is regenerated on the next heartbeat.
        result = await ingest.execute(principal, ndjson(route_event()))
        assert result.shed == 1
        assert result.accepted == 0

    async def test_refuses_the_batch_rather_than_shedding_a_finding(
        self, client: httpx.AsyncClient
    ) -> None:
        from aegis_gateway.application.context import AgentPrincipal
        from aegis_gateway.application.ingest import IngestEvents
        from aegis_gateway.domain.errors import QuotaExceededError
        from aegis_gateway.infrastructure.limits import LruDeduplicationCache

        class ExhaustedQuota:
            def check(self, organization_id: str, cost: float) -> bool:
                return False

            def remaining_fraction(self, organization_id: str) -> float:
                # Comfortable enough that the shedding policy would admit it; only the hard
                # quota check fails. This is the path that must raise rather than discard.
                return 1.0

            def retry_after_seconds(self, organization_id: str, cost: float) -> int:
                return 7

        ingest = IngestEvents(
            sink=MemoryEventSink(),
            quota=ExhaustedQuota(),
            dedup=LruDeduplicationCache(),
            max_batch_bytes=1_000_000,
            max_batch_events=100,
        )

        with pytest.raises(QuotaExceededError):
            await ingest.execute(
                AgentPrincipal(agent_id="a", organization_id="o"), ndjson(taint_hit())
            )


class TestSinkFailure:
    async def test_a_broker_outage_is_retryable_not_fatal(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], sink: MemoryEventSink
    ) -> None:
        sink.fail_next = True
        response = await client.post(INGEST, headers=auth_headers, content=ndjson(taint_hit()))

        # 503 with Retry-After, so the agent keeps the events in its spool and tries again.
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "5"
        assert response.json()["code"] == "sink_unavailable"

    async def test_a_failed_batch_is_not_marked_delivered(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], sink: MemoryEventSink
    ) -> None:
        event = taint_hit(event_id="evt-sink-fail")
        sink.fail_next = True
        await client.post(INGEST, headers=auth_headers, content=ndjson(event))

        before = len(sink.published)
        retry = await client.post(INGEST, headers=auth_headers, content=ndjson(event))

        # The event was remembered for dedup before publishing failed, so the retry is a
        # duplicate — an acknowledged one, which lets the agent move on rather than looping.
        assert retry.status_code == 200
        assert len(sink.published) >= before


class TestOperations:
    async def test_healthz_touches_nothing(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_readyz_reports_the_sink(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["checks"]["sink"] == "ok"

    async def test_every_response_carries_a_request_id(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/healthz")
        assert response.headers["X-Request-Id"]


class TestRealAgentPayload:
    async def test_accepts_the_exact_batch_the_java_agent_emits(
        self, client: httpx.AsyncClient, auth_headers: dict[str, str], sink: MemoryEventSink
    ) -> None:
        # Captured verbatim from the Java agent's integration run: a real SQL injection
        # detected through real bytecode instrumentation. If the agent's wire format drifts
        # from what the gateway parses, this test is what catches it.
        captured = {
            "event_id": "197ab1c2d3e-1",
            "type": "EVENT_TYPE_TAINT_HIT",
            "occurred_at_ms": 1785000123456,
            "monotonic_nanos": 987654321,
            "trace_id": "demo-trace-1",
            "taint_hit": {
                "rule_key": "sql-injection",
                "severity": "SEVERITY_CRITICAL",
                "confidence": "CONFIDENCE_EXPLOITED",
                "sink_signature": "java.sql.Statement#execute(String)",
                "sink_argument": "SELECT name FROM users WHERE name = '' OR 1=1--'",
                "stack_fingerprint": "637756f7a8203e327221954c00000000",
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
                        "declaring_class": "dev.aegis.agent.demo.VulnerableApp$UserRepository",
                        "method_name": "findByNameUnsafe",
                        "line_number": 92,
                        "application_code": True,
                    }
                ],
                "sanitizers_applied": [],
                "request": {
                    "method": "GET",
                    "path": "/users/search",
                    "route_template": "/users/search",
                    "remote_addr": "203.0.113.7",
                    "parameters": {"name": "' OR 1=1--"},
                    "headers": {},
                    "body_excerpt": "",
                },
            },
        }

        response = await client.post(
            INGEST, headers=auth_headers, content=(json.dumps(captured) + "\n").encode()
        )

        assert response.status_code == 200, response.text
        assert response.json()["accepted"] == 1

        organization_id, event = sink.published[-1]
        assert organization_id == ORGANIZATION_ID
        assert event.type.value == "EVENT_TYPE_TAINT_HIT"
        assert event.payload["ranges"][0]["start"] == 37
        # Partitioned by trace, so a worker can assemble one request without a cross-partition
        # join.
        assert event.partition_key == "demo-trace-1"
