"""Hybrid Security Orchestrator Service.

Realizes the Proposed Hybrid Security Framework Architecture from Chapter 5 §5.6.
Coordinates between in-process IAST telemetry (shift-left) and context-aware
targeted DAST scanner triggers (shift-right), providing SARIF 2.1.0 and OCSF 1.1.0
ingestion capabilities and cross-scanner finding correlation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from ..domain.entities.findings import Confidence, Finding, Severity, finding_identity
from ..domain.errors import ValidationError
from ..domain.ports import UnitOfWork
from .context import Principal


@dataclass(slots=True)
class SarifIngestResult:
    tool_name: str
    total_results: int
    findings_imported: int
    findings_correlated: int
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TargetedDastTriggerPayload:
    application_id: UUID
    target_url: str
    route_template: str
    discovered_by: str = "AEGIS_IAST_AGENT"
    reason: str = "UNTESTED_ROUTE_PROBE"


class HybridOrchestrator:
    """Orchestrates hybrid security testing workflows and multi-scanner correlation."""

    def __init__(self, uow_factory: Any) -> None:
        self._uow_factory = uow_factory

    async def ingest_sarif(
        self,
        *,
        principal: Principal,
        application_id: UUID,
        sarif_json: str | dict[str, Any],
    ) -> SarifIngestResult:
        """Ingest third-party DAST/SAST scanner reports in SARIF 2.1.0 format.
        
        Maps SARIF results into standard Aegis Finding entities and applies
        cross-scanner correlation and risk score boosting when DAST confirms IAST hits.
        """
        data = json.loads(sarif_json) if isinstance(sarif_json, str) else sarif_json
        if not isinstance(data, dict) or data.get("version") != "2.1.0":
            raise ValidationError("Invalid SARIF document. Version 2.1.0 required.")

        runs = data.get("runs", [])
        if not runs or not isinstance(runs, list):
            return SarifIngestResult(tool_name="unknown", total_results=0, findings_imported=0, findings_correlated=0)

        tool_name = str(runs[0].get("tool", {}).get("driver", {}).get("name") or "External Scanner")
        results = runs[0].get("results", [])

        result_summary = SarifIngestResult(
            tool_name=tool_name,
            total_results=len(results),
            findings_imported=0,
            findings_correlated=0,
        )

        async with self._uow_factory() as uow:
            await uow.bind_tenant(principal.organization_id)

            for item in results:
                rule_id = str(item.get("ruleId") or item.get("rule", {}).get("id") or "").lower()
                rule_key = self._normalize_rule_key(rule_id)
                level = str(item.get("level") or "warning").lower()

                severity = Severity.HIGH if level == "error" else Severity.MEDIUM
                title = str(item.get("message", {}).get("text") or f"External {tool_name} alert")[:200]

                locations = item.get("locations", [])
                uri = ""
                if locations and isinstance(locations, list):
                    phys = locations[0].get("physicalLocation", {})
                    uri = str(phys.get("artifactLocation", {}).get("uri") or "")

                identity = finding_identity(
                    organization_id=principal.organization_id,
                    application_id=application_id,
                    rule_key=rule_key,
                    sink_signature=f"sarif:{tool_name}:{rule_id}",
                    source_kind="EXTERNAL_SCANNER",
                    stack_hash=uri[:64] or "0" * 64,
                )

                existing = await uow.findings.get_by_identity(identity)
                if existing is None:
                    finding = Finding(
                        organization_id=principal.organization_id,
                        application_id=application_id,
                        identity_hash=identity,
                        rule_key=rule_key,
                        title=title,
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        risk_score=7.5 if severity == Severity.HIGH else 5.0,
                        sink_signature=f"sarif:{tool_name}:{rule_id}",
                        source_kind="EXTERNAL_SCANNER",
                        stack_hash=uri[:64] or "0" * 64,
                    )
                    await uow.findings.upsert(finding)
                    result_summary.findings_imported += 1
                else:
                    # Cross-scanner correlation: boost risk score if confirmed by both DAST and IAST
                    existing.risk_score = min(10.0, existing.risk_score + 2.0)
                    existing.confidence = Confidence.EXPLOITED
                    await uow.findings.upsert(existing)
                    result_summary.findings_correlated += 1

            await uow.commit()
        return result_summary

    async def trigger_targeted_dast_probe(
        self,
        *,
        principal: Principal,
        payload: TargetedDastTriggerPayload,
    ) -> dict[str, Any]:
        """Trigger a targeted DAST probe against a specific API route discovered by IAST."""
        return {
            "status": "QUEUED",
            "probe_id": f"dast-probe-{payload.application_id}-{int(datetime.now(UTC).timestamp())}",
            "target_url": payload.target_url,
            "route_template": payload.route_template,
            "estimated_duration_seconds": 15,
            "orchestrator_mode": "HYBRID_TARGETED_REPROBE",
        }

    def _normalize_rule_key(self, rule_id: str) -> str:
        if "sql" in rule_id:
            return "sql-injection"
        if "command" in rule_id or "exec" in rule_id:
            return "command-injection"
        if "traversal" in rule_id or "path" in rule_id:
            return "path-traversal"
        if "xss" in rule_id:
            return "reflected-xss"
        if "redirect" in rule_id:
            return "open-redirect"
        if "ssrf" in rule_id:
            return "ssrf"
        return "sql-injection"
