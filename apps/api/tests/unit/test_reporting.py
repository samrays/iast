"""Unit tests for compliance mapping and attestation reporting engine."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aegis_api.application.context import Principal
from aegis_api.application.reporting import FRAMEWORK_MAPPINGS, GenerateComplianceReport
from aegis_api.domain.entities.findings import Confidence, Finding, Severity
from aegis_api.domain.permissions import Permission

NOW = datetime(2026, 7, 30, tzinfo=UTC)


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "organization_id": uuid4(),
        "application_id": uuid4(),
        "identity_hash": "a" * 64,
        "rule_key": "sql-injection",
        "title": "SQL Injection in UserRepository",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.EXPLOITED,
        "sink_signature": "java.sql.Statement#execute",
        "source_kind": "PARAMETER",
        "stack_hash": "b" * 64,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestFrameworkMappings:
    def test_framework_mapping_keys_exist(self) -> None:
        assert "sql-injection" in FRAMEWORK_MAPPINGS
        assert "command-injection" in FRAMEWORK_MAPPINGS
        sql_map = FRAMEWORK_MAPPINGS["sql-injection"]
        assert "pci_dss" in sql_map
        assert "soc_2" in sql_map
        assert "iso_27001" in sql_map
        assert "nist_800_53" in sql_map
        assert "owasp_asvs" in sql_map
