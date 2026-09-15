"""Export findings into SARIF v2.1.0, OCSF v1.1.0, and CEF syslog formats.

Provides integrations for GitHub Code Scanning, enterprise SIEMs (Splunk, QRadar, ArcSight),
and SOC log pipelines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable
from uuid import UUID

from ..domain.entities.findings import Finding, Severity
from ..domain.permissions import Permission
from ..domain.ports import UnitOfWork
from .context import Principal

# SARIF severity mapping
_SARIF_LEVEL_MAP = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# OCSF Severity ID mapping (1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical)
_OCSF_SEVERITY_ID_MAP = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class SarifExporter:
    """Renders findings in SARIF v2.1.0 JSON format for CI/CD code scanning."""

    @staticmethod
    def export(findings: list[Finding]) -> dict[str, Any]:
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        rule_indices: dict[str, int] = {}

        for finding in findings:
            if finding.rule_key not in rule_indices:
                idx = len(rules)
                rule_indices[finding.rule_key] = idx
                rules.append({
                    "id": finding.rule_key,
                    "name": finding.rule_key.replace("-", " ").title(),
                    "shortDescription": {"text": f"Vulnerability rule: {finding.rule_key}"},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL_MAP.get(finding.severity, "warning")
                    },
                })

            rule_idx = rule_indices[finding.rule_key]
            results.append({
                "ruleId": finding.rule_key,
                "ruleIndex": rule_idx,
                "level": _SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                "message": {
                    "text": f"IAST detected {finding.rule_key} vulnerability at sink {finding.sink_signature}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.sink_signature},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "finding_id": str(finding.id),
                    "status": finding.status.value,
                    "confidence": finding.confidence.value,
                    "risk_score": finding.risk_score,
                },
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Aegis IAST",
                            "version": "0.2.0",
                            "informationUri": "https://aegis.security",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }


class SiemExporter:
    """Renders findings in OCSF (v1.1.0) and CEF syslog formats."""

    @staticmethod
    def to_ocsf(finding: Finding, now: datetime) -> dict[str, Any]:
        """Convert a single finding into OCSF Vulnerability Finding event (class_uid: 2002)."""
        created_sec = int(finding.created_at.timestamp()) if finding.created_at else int(now.timestamp())
        return {
            "class_uid": 2002,
            "class_name": "Vulnerability Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": _OCSF_SEVERITY_ID_MAP.get(finding.severity, 3),
            "severity": finding.severity.value,
            "time": int(now.timestamp()),
            "activity_id": 1,
            "activity_name": "Create",
            "finding_info": {
                "uid": str(finding.id),
                "title": f"{finding.rule_key} vulnerability in {finding.sink_signature}",
                "desc": f"Observed {finding.rule_key} with confidence {finding.confidence.value}",
                "created_time": created_sec,
                "status": finding.status.value,
                "src_url": finding.sink_signature,
            },
            "vulnerabilities": [
                {
                    "name": finding.rule_key,
                    "severity": finding.severity.value,
                    "is_exploit_available": finding.confidence.value == "EXPLOITED",
                }
            ],
        }

    @staticmethod
    def to_cef(finding: Finding, now: datetime) -> str:
        """Convert a single finding into Common Event Format (CEF) syslog text string."""
        sev_int = _OCSF_SEVERITY_ID_MAP.get(finding.severity, 3) * 2  # Scale 1-5 to 2-10
        signature_id = finding.rule_key
        name = f"Aegis IAST Finding: {finding.rule_key}"
        ext_parts = [
            f"cn1={finding.risk_score}",
            "cn1Label=RiskScore",
            f"cs1={finding.sink_signature}",
            "cs1Label=SinkSignature",
            f"cs2={finding.status.value}",
            "cs2Label=FindingStatus",
            f"cs3={finding.confidence.value}",
            "cs3Label=Confidence",
            f"externalId={finding.id}",
        ]
        ext = " ".join(ext_parts)
        return f"CEF:0|Aegis|IAST|0.2.0|{signature_id}|{name}|{sev_int}|{ext}"


class ExportFindings:
    """Use case to retrieve findings and render in the requested export format."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def execute(
        self,
        *,
        principal: Principal,
        fmt: str = "sarif",
        application_id: UUID | None = None,
    ) -> tuple[dict[str, Any] | str, str]:
        principal.require(Permission.FINDING_READ)

        async with self._uow_factory() as uow:
            await uow.bind_tenant(principal.organization_id)
            findings, _ = await uow.findings.list_all(
                limit=1000,
                cursor=None,
                statuses=["OPEN", "CONFIRMED"],
                application_id=application_id,
            )

            fmt_lower = fmt.lower()
            if fmt_lower == "sarif":
                return SarifExporter.export(findings), "application/sarif+json"
            if fmt_lower == "ocsf":
                now = datetime.now()
                events = [SiemExporter.to_ocsf(f, now) for f in findings]
                return {"ocsf_events": events}, "application/json"
            if fmt_lower == "cef":
                now = datetime.now()
                cef_lines = [SiemExporter.to_cef(f, now) for f in findings]
                return "\n".join(cef_lines), "text/plain"

            raise ValueError(f"Unsupported export format: {fmt}")


__all__ = ["ExportFindings", "SarifExporter", "SiemExporter"]
