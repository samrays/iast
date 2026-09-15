"""Compliance mapping and attestation reporting engine.

Maps findings against security compliance standards:
- PCI DSS 4.0
- SOC 2 Trust Services Criteria
- ISO 27001:2022
- NIST 800-53 Rev. 5
- OWASP ASVS 4.0
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import UUID

from ..domain.permissions import Permission
from ..domain.ports import Clock, UnitOfWork
from .context import Principal

FRAMEWORK_MAPPINGS: dict[str, dict[str, str]] = {
    "sql-injection": {
        "pci_dss": "6.2.4 - Software development & injection flaws",
        "soc_2": "CC6.6 - Boundary protection & application firewalls",
        "iso_27001": "A.8.28 - Secure coding principles",
        "nist_800_53": "SI-10 - Information Input Validation",
        "owasp_asvs": "V5.3 - Output Encoding and Injection Prevention",
    },
    "command-injection": {
        "pci_dss": "6.2.4 - System command injection prevention",
        "soc_2": "CC6.1 - Logical access security controls",
        "iso_27001": "A.8.28 - Secure coding principles",
        "nist_800_53": "SI-10 - Input Sanitization",
        "owasp_asvs": "V5.2 - Command Execution Prevention",
    },
    "path-traversal": {
        "pci_dss": "6.2.4 - Unrestricted file upload & access control",
        "soc_2": "CC6.1 - System boundary isolation",
        "iso_27001": "A.8.12 - Data leakage prevention",
        "nist_800_53": "AC-3 - Access Enforcement",
        "owasp_asvs": "V12.1 - File Operation Security",
    },
    "unsafe-deserialization": {
        "pci_dss": "6.2.4 - Malicious object deserialization",
        "soc_2": "CC6.8 - Software integrity controls",
        "iso_27001": "A.8.28 - Secure coding",
        "nist_800_53": "SI-16 - Memory Protection",
        "owasp_asvs": "V5.5 - Deserialization Security",
    },
    "xxe": {
        "pci_dss": "6.2.4 - XML external entity prevention",
        "soc_2": "CC6.6 - Application security testing",
        "iso_27001": "A.8.28 - Secure coding",
        "nist_800_53": "SI-10 - XML Input Parsing",
        "owasp_asvs": "V5.5 - XML Parser Configuration",
    },
    "reflected-xss": {
        "pci_dss": "6.2.4 - Cross-site scripting (XSS) prevention",
        "soc_2": "CC6.6 - Web application firewalls & output encoding",
        "iso_27001": "A.8.28 - Secure coding",
        "nist_800_53": "SI-10 - Output Sanitization",
        "owasp_asvs": "V5.3 - Output Encoding & Context Escaping",
    },
    "ssrf": {
        "pci_dss": "6.2.4 - Server-side request forgery prevention",
        "soc_2": "CC6.6 - Network boundary security",
        "iso_27001": "A.8.20 - Network security management",
        "nist_800_53": "SC-7 - Boundary Protection",
        "owasp_asvs": "V12.6 - SSRF Protection",
    },
}


class GenerateComplianceReport:
    """Generate compliance attestation report for security frameworks."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork], clock: Clock) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def execute(
        self,
        *,
        principal: Principal,
        framework: str = "pci_dss",
        application_id: UUID | None = None,
        fmt: str = "json",
    ) -> tuple[dict[str, Any] | str, str]:
        principal.require_permission(Permission.FINDING_READ)

        async with self._uow_factory() as uow:
            await uow.bind_tenant(principal.organization_id)

            # Query non-remediated findings
            findings, _ = await uow.findings.list_all(
                limit=1000,
                cursor=None,
                statuses=["OPEN", "CONFIRMED"],
                application_id=application_id,
            )

            now = self._clock.now()
            mappings: list[dict[str, Any]] = []
            open_gaps = 0

            for f in findings:
                fw_map = FRAMEWORK_MAPPINGS.get(f.rule_key, {})
                control = fw_map.get(framework.lower(), "General Application Security")
                open_gaps += 1

                mappings.append({
                    "finding_id": str(f.id),
                    "rule_key": f.rule_key,
                    "severity": f.severity.value,
                    "sink_signature": f.sink_signature,
                    "control": control,
                    "status": f.status.value,
                })

            eval_count = len(findings)
            score = round(max(0.0, 100.0 - (open_gaps * 5.0)), 1)

            report_data = {
                "organization_id": str(principal.organization_id),
                "framework": framework.upper(),
                "generated_at": now.isoformat(),
                "total_findings_evaluated": eval_count,
                "open_gaps_count": open_gaps,
                "compliance_score": score,
                "control_mappings": mappings,
            }

            if fmt.lower() == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["Finding ID", "Rule Key", "Severity", "Sink Signature", "Compliance Control", "Status"])
                for m in mappings:
                    writer.writerow([
                        m["finding_id"],
                        m["rule_key"],
                        m["severity"],
                        m["sink_signature"],
                        m["control"],
                        m["status"],
                    ])
                return output.getvalue(), "text/csv"

            return report_data, "application/json"


__all__ = ["FRAMEWORK_MAPPINGS", "GenerateComplianceReport"]
