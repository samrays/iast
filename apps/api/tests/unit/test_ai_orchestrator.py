"""Unit tests for AI Graph Orchestrator."""

from datetime import datetime
from uuid import uuid4

import pytest

from typing import Any

from aegis_api.application.ai import ModelResponse
from aegis_api.application.ai_orchestrator import AiGraphOrchestrator
from aegis_api.application.context import Principal
from aegis_api.domain.entities import ActorType
from aegis_api.domain.entities.findings import Confidence, Finding, FindingStatus, Severity
from aegis_api.domain.permissions import Permission


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "organization_id": uuid4(),
        "application_id": uuid4(),
        "identity_hash": "d" * 64,
        "rule_key": "sql-injection",
        "title": "SQL Injection in UserDAO",
        "severity": Severity.HIGH,
        "confidence": Confidence.CONFIRMED,
        "sink_signature": "java.sql.Statement#executeQuery(java.lang.String)",
        "source_kind": "PARAMETER",
        "stack_hash": "e" * 64,
        "status": FindingStatus.OPEN,
        "risk_score": 8.0,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class FakeLanguageModel:
    def __init__(self, response_text: str = "Use prepared statements to fix SQL injection.") -> None:
        self.response_text = response_text

    async def complete(self, *, system: str, user: str, max_output_tokens: int) -> ModelResponse:
        return ModelResponse(
            summary="Root cause summary",
            content=self.response_text,
            model="test-model",
            input_tokens=100,
            output_tokens=50,
        )


@pytest.mark.asyncio
async def test_ai_graph_orchestrator_execution(container: Any) -> None:
    from aegis_api.domain.entities import Application, Language, Organization
    from aegis_api.domain.value_objects import Slug

    async with container.unit_of_work() as uow:
        org = Organization(name="Test Org", slug=Slug("test-org"))
        await uow.organizations.add(org)
        await uow.bind_tenant(org.id)
        app = Application(organization_id=org.id, name="Test App", slug=Slug("test-app"), language=Language.JAVA)
        await uow.applications.add(app)
        finding = make_finding(organization_id=org.id, application_id=app.id)
        await uow.findings.upsert(finding)
        await uow.commit()

    principal = Principal(
        kind=ActorType.USER,
        user_id=uuid4(),
        organization_id=org.id,
        permissions=frozenset({Permission.AI_RUN}),
    )

    fake_model = FakeLanguageModel()
    from aegis_api.infrastructure.clock import SystemClock

    orchestrator = AiGraphOrchestrator(container.unit_of_work, fake_model, SystemClock())
    result = await orchestrator.execute_graph(principal=principal, finding_id=finding.id)
    assert result.finding_id == finding.id
    assert result.guardrail_passed is True
    assert len(result.compliance_controls) > 0


def test_ai_graph_guardrail_sanitization() -> None:
    fake_model = FakeLanguageModel(response_text="Run `rm -rf /` to fix the system.")
    from aegis_api.infrastructure.clock import SystemClock

    orchestrator = AiGraphOrchestrator(None, fake_model, SystemClock())  # type: ignore[arg-type]
    sanitized = orchestrator._guardrail_sanitize(fake_model.response_text)
    assert "REDACTED BY AI GUARDRAIL" in sanitized
