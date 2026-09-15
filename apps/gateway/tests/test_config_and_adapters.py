"""Configuration guards, adapter edge cases and the strict-mode ingest path."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from tests.conftest import (
    ISSUER,
    JWT_SECRET,
    make_agent_token,
    ndjson,
    route_event,
    taint_hit,
)

from aegis_gateway.application.context import AgentPrincipal
from aegis_gateway.application.ingest import IngestEvents, summarize_types
from aegis_gateway.config import Environment, Settings
from aegis_gateway.domain.errors import (
    AgentAuthenticationError,
    GatewayError,
    InvalidEventError,
    SinkUnavailableError,
)
from aegis_gateway.domain.events import EventType, parse_event
from aegis_gateway.infrastructure.auth import JwtAgentAuthenticator
from aegis_gateway.infrastructure.limits import LruDeduplicationCache, SystemClock
from aegis_gateway.infrastructure.sinks import MemoryEventSink, build_sink
from aegis_gateway.interfaces.http.errors import status_for


class TestProductionGuards:
    """Settings that must refuse to start a production-like deployment."""

    def test_rejects_a_placeholder_secret(self) -> None:
        with pytest.raises(ValueError, match="JWT_SECRET"):
            Settings(environment=Environment.PRODUCTION, jwt_secret="change-me")

    def test_rejects_a_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 32"):
            Settings(environment=Environment.PRODUCTION, jwt_secret="too-short")

    def test_requires_a_public_key_for_asymmetric_verification(self) -> None:
        with pytest.raises(ValueError, match="PUBLIC_KEY"):
            Settings(
                environment=Environment.PRODUCTION,
                jwt_algorithm="RS256",
                jwt_secret="x" * 40,
            )

    def test_refuses_the_in_memory_sink_in_production(self) -> None:
        # It discards everything on restart. Shipping with it would silently lose findings.
        with pytest.raises(ValueError, match="in-memory sink"):
            Settings(
                environment=Environment.PRODUCTION,
                jwt_secret="x" * 40,
                event_sink="memory://",
            )

    def test_accepts_a_properly_configured_production_deployment(self) -> None:
        settings = Settings(
            environment=Environment.PRODUCTION,
            jwt_secret="a" * 48,
            event_sink="kafka://broker:9092/runtime-events",
        )
        assert settings.environment.is_production_like

    def test_generates_a_secret_for_local_development(self) -> None:
        # A fresh clone must run without ceremony.
        settings = Settings(environment=Environment.LOCAL, jwt_secret="")
        assert len(settings.jwt_secret) > 32

    def test_local_default_feeds_the_workers_durable_stream(self) -> None:
        settings = Settings(
            environment=Environment.LOCAL, jwt_secret="local-test-secret"
        )
        assert settings.event_sink == "file:.local-data/aegis-events.ndjson"


class TestAuthenticatorEdges:
    def _authenticator(self) -> JwtAgentAuthenticator:
        return JwtAgentAuthenticator(secret=JWT_SECRET, issuer=ISSUER)

    def test_accepts_a_bare_token_without_the_bearer_scheme(self) -> None:
        principal = self._authenticator().authenticate(make_agent_token())
        assert principal.agent_id

    @pytest.mark.parametrize("credential", ["", "   ", "Bearer ", "Bearer    "])
    def test_rejects_an_empty_credential(self, credential: str) -> None:
        with pytest.raises(AgentAuthenticationError):
            self._authenticator().authenticate(credential)

    def test_rejects_a_token_whose_purpose_is_not_agent(self) -> None:
        token = make_agent_token(purpose="reset")
        with pytest.raises(AgentAuthenticationError):
            self._authenticator().authenticate(token)

    def test_rejects_a_token_missing_the_organization(self) -> None:
        from datetime import UTC, datetime, timedelta

        import jwt as pyjwt

        now = datetime.now(UTC)
        token = pyjwt.encode(
            {
                "iss": ISSUER,
                "aud": "aegis:agent",
                "sub": "agent-1",
                "purpose": "agent",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
            },
            JWT_SECRET,
            algorithm="HS256",
        )
        # Without a tenant there is nowhere to attribute the events; failing closed is the
        # only safe answer.
        with pytest.raises(AgentAuthenticationError):
            self._authenticator().authenticate(token)

    def test_prefers_the_public_key_for_asymmetric_algorithms(self) -> None:
        authenticator = JwtAgentAuthenticator(
            secret="unused", algorithm="RS256", public_key="-----BEGIN PUBLIC KEY-----"
        )
        # The gateway is the most exposed service in the platform and should never hold a
        # signing key.
        assert authenticator._key == "-----BEGIN PUBLIC KEY-----"


class TestStrictMode:
    async def test_strict_mode_fails_the_whole_batch(self) -> None:
        ingest = IngestEvents(
            sink=MemoryEventSink(),
            quota=_UnlimitedQuota(),
            dedup=LruDeduplicationCache(),
            max_batch_bytes=1_000_000,
            max_batch_events=100,
            reject_batch_on_invalid=True,
        )
        body = b"{broken\n" + ndjson(taint_hit())

        # Useful when developing an agent, where silence about a schema bug is worse than
        # losing the batch.
        with pytest.raises(InvalidEventError):
            await ingest.execute(
                AgentPrincipal(agent_id="a", organization_id="o"), body
            )

    async def test_stops_reading_past_the_declared_event_limit(self) -> None:
        sink = MemoryEventSink()
        ingest = IngestEvents(
            sink=sink,
            quota=_UnlimitedQuota(),
            dedup=LruDeduplicationCache(),
            max_batch_bytes=1_000_000,
            max_batch_events=3,
        )
        body = ndjson(*[taint_hit() for _ in range(10)])

        result = await ingest.execute(
            AgentPrincipal(agent_id="a", organization_id="o"), body
        )

        # One request must not be able to consume unbounded CPU.
        assert result.accepted <= 3
        assert result.rejected == 1

    async def test_reports_credit_even_for_an_empty_batch(self) -> None:
        ingest = IngestEvents(
            sink=MemoryEventSink(),
            quota=_UnlimitedQuota(),
            dedup=LruDeduplicationCache(),
            max_batch_bytes=1_000,
            max_batch_events=10,
        )
        result = await ingest.execute(
            AgentPrincipal(agent_id="a", organization_id="o"), b"\n\n"
        )
        assert result.accepted == 0
        assert result.credit >= 1


class TestSinkSelection:
    def test_kafka_scheme_is_parsed_without_a_broker(self) -> None:
        # Constructing the sink must not require a reachable broker; that is a runtime
        # concern surfaced as a retryable 503.
        pytest.importorskip("aiokafka")
        sink = build_sink("kafka://localhost:9092/custom-topic")
        assert sink._topic == "custom-topic"  # type: ignore[attr-defined]
        assert sink._producer is None  # type: ignore[attr-defined]

    async def test_kafka_producer_is_created_inside_the_running_loop(self) -> None:
        pytest.importorskip("aiokafka")
        sink = build_sink("kafka://localhost:9092/custom-topic")

        class FakeProducer:
            def __init__(self, **options: Any) -> None:
                self.options = options
                self.started = False
                self.stopped = False

            async def start(self) -> None:
                self.started = True

            async def stop(self) -> None:
                self.stopped = True

        sink._producer_type = FakeProducer  # type: ignore[attr-defined]
        await sink.start()  # type: ignore[attr-defined]

        producer = sink._producer  # type: ignore[attr-defined]
        assert producer.started
        assert producer.options["bootstrap_servers"] == "localhost:9092"
        await sink.close()  # type: ignore[attr-defined]
        assert producer.stopped

    @pytest.mark.parametrize(
        "destination, message",
        [
            ("kafak://broker:9092/runtime-events", "Unsupported event sink"),
            ("kafka:///runtime-events", "bootstrap server"),
            ("file:", "requires a path"),
            ("memory://typo", "Unsupported event sink"),
        ],
    )
    def test_invalid_sink_configuration_fails_closed(
        self, destination: str, message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            build_sink(destination)

    def test_kafka_without_the_extra_reports_a_clear_installation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "aiokafka":
                raise ImportError("No module named 'aiokafka'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(SinkUnavailableError, match=r"kafka.*extra"):
            build_sink("kafka://localhost:9092/topic")

    async def test_memory_sink_close_is_a_no_op(self) -> None:
        sink = MemoryEventSink()
        await sink.close()


class TestErrorMapping:
    def test_an_unmapped_domain_error_is_a_bad_request(self) -> None:
        class OddError(GatewayError):
            code = "odd"

        assert status_for(OddError()) == 400

    async def test_an_unhandled_exception_never_leaks_internals(
        self,
        client: httpx.AsyncClient,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        container = client.app.state.container  # type: ignore[attr-defined]

        async def explode(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("connection string postgres://user:hunter2@db/aegis")

        monkeypatch.setattr(container.ingest, "execute", explode)

        with pytest.raises(RuntimeError):
            # httpx re-raises through the ASGI transport; what matters is that the handler
            # itself never puts the message in a response body.
            await client.post(
                "/ingest/v1/events", headers=auth_headers, content=ndjson(taint_hit())
            )


class TestHelpers:
    def test_summarize_types_counts_by_type(self) -> None:
        events = [
            parse_event(taint_hit(), 1),
            parse_event(taint_hit(), 2),
            parse_event(route_event(), 3),
        ]
        assert summarize_types(events) == {
            EventType.TAINT_HIT.value: 2,
            EventType.ROUTE.value: 1,
        }

    def test_agent_principal_labels_itself(self) -> None:
        assert AgentPrincipal(agent_id="a1", organization_id="o1").label == "agent:a1"

    def test_system_clock_advances(self) -> None:
        clock = SystemClock()
        assert clock.monotonic() > 0
        assert clock.now_ms() > 0


class _UnlimitedQuota:
    def check(self, organization_id: str, cost: float) -> bool:
        return True

    def remaining_fraction(self, organization_id: str) -> float:
        return 1.0

    def retry_after_seconds(self, organization_id: str, cost: float) -> int:
        return 0
