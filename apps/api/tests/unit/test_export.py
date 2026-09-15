"""Unit tests for SARIF, OCSF, and CEF export formats."""

from datetime import datetime
from uuid import uuid4

import pytest

from aegis_api.application.export import ExportFindings, SarifExporter, SiemExporter
from aegis_api.domain.entities.findings import Confidence, Finding, FindingStatus, Severity


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
        "risk_score": 8.5,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_sarif_export() -> None:
    finding = make_finding()
    result = SarifExporter.export([finding])
    assert result["version"] == "2.1.0"
    assert len(result["runs"]) == 1
    run = result["runs"][0]
    assert run["tool"]["driver"]["name"] == "Aegis IAST"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "sql-injection"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == finding.sink_signature


def test_ocsf_export() -> None:
    finding = make_finding()
    now = datetime(2026, 8, 12, 12, 0, 0)
    event = SiemExporter.to_ocsf(finding, now)
    assert event["class_uid"] == 2002
    assert event["class_name"] == "Vulnerability Finding"
    assert event["severity"] == "HIGH"
    assert event["severity_id"] == 4
    assert event["finding_info"]["uid"] == str(finding.id)


def test_cef_export() -> None:
    finding = make_finding()
    now = datetime(2026, 8, 12, 12, 0, 0)
    cef_line = SiemExporter.to_cef(finding, now)
    assert cef_line.startswith("CEF:0|Aegis|IAST|0.2.0|sql-injection|")
    assert f"externalId={finding.id}" in cef_line
    assert "cn1=8.5" in cef_line
