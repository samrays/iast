"""SIEM export: OCSF for modern platforms, CEF for the ones already deployed.

Findings belong in the same place as the rest of a security team's telemetry. Two formats,
because the market is split: OCSF is where Splunk, AWS Security Lake and Sumo are heading, and
CEF is what a decade of ArcSight/QRadar deployments already parse.

**The escaping in this module is a security control, not formatting.** A finding carries the
attacker's payload — that is the point of it — and CEF is a flat `key=value` line. An
unescaped `=` or newline in a sink argument lets an attacker inject fabricated fields into the
customer's SIEM: forged severities, forged source addresses, or a synthetic second event.
Shipping a security product that gives attackers a write primitive into the SOC's own console
would be worse than shipping nothing.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ..domain.entities.findings import Confidence, Finding, FindingStatus, Occurrence, Severity
from ..domain.permissions import Permission
from ..domain.ports import UnitOfWork
from .context import Principal
from .findings import TITLE_BY_RULE

# --- OCSF ---------------------------------------------------------------------------

OCSF_VERSION = "1.1.0"
#: Vulnerability Finding, in the Findings category.
OCSF_CLASS_UID = 2002
OCSF_CATEGORY_UID = 2

_OCSF_SEVERITY_ID: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

#: OCSF's finding status vocabulary, which does not line up with ours one-for-one. New and
#: In Progress both mean "somebody still has to act"; Suppressed and Resolved both mean nobody
#: does. Mapping to the nearest honest neighbour beats inventing a status the consumer will
#: not recognise.
_OCSF_STATUS: dict[FindingStatus, tuple[int, str]] = {
    FindingStatus.OPEN: (1, "New"),
    FindingStatus.CONFIRMED: (2, "In Progress"),
    FindingStatus.REMEDIATED: (3, "Resolved"),
    FindingStatus.FALSE_POSITIVE: (4, "Suppressed"),
    FindingStatus.ACCEPTED_RISK: (4, "Suppressed"),
}

_OCSF_CONFIDENCE_ID = {Confidence.SUSPECTED: 1, Confidence.CONFIRMED: 2, Confidence.EXPLOITED: 3}


def _millis(value: Any) -> int | None:
    return int(value.timestamp() * 1000) if value is not None else None


def to_ocsf(
    finding: Finding, occurrence: Occurrence | None, *, product_version: str
) -> dict[str, Any]:
    """One OCSF Vulnerability Finding event."""
    status_id, status = _OCSF_STATUS.get(finding.status, (0, "Unknown"))
    # Activity 1 is Create, 2 is Update. Anything seen more than once is an update, which is
    # what stops a SIEM counting one defect as thousands of separate incidents.
    activity_id = 1 if finding.occurrence_count <= 1 else 2

    vulnerability: dict[str, Any] = {
        "title": finding.title,
        "desc": f"{finding.source_kind.lower()} data reaches {finding.sink_signature}",
        "severity": finding.severity.value.title(),
        # Not "could be exploited" — the agent saw the payload arrive at the sink.
        "is_exploit_available": finding.confidence is Confidence.EXPLOITED,
        "first_seen_time": _millis(finding.first_seen_at),
        "last_seen_time": _millis(finding.last_seen_at),
    }
    if finding.cwe_id is not None:
        vulnerability["cwe"] = {
            "uid": f"CWE-{finding.cwe_id}",
            "caption": TITLE_BY_RULE.get(finding.rule_key, finding.rule_key),
        }
    if occurrence is not None:
        frame = next((f for f in occurrence.stack_frames if f[3]), None)
        if frame is not None:
            declaring_class, _method, line, _is_app = frame
            affected: dict[str, Any] = {
                "file": {"path": declaring_class.split("$", 1)[0].replace(".", "/") + ".java"}
            }
            if line > 0:
                affected["start_line"] = line
            vulnerability["affected_code"] = [affected]

    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": OCSF_CATEGORY_UID,
        "class_uid": OCSF_CLASS_UID,
        "type_uid": OCSF_CLASS_UID * 100 + activity_id,
        "time": _millis(finding.last_seen_at),
        "severity_id": _OCSF_SEVERITY_ID.get(finding.severity, 0),
        "severity": finding.severity.value.title(),
        "status_id": status_id,
        "status": status,
        "confidence_id": _OCSF_CONFIDENCE_ID.get(finding.confidence, 0),
        "confidence": finding.confidence.value.title(),
        "finding_info": {
            # The deterministic identity, so the SIEM correlates across runs the same way we do.
            "uid": finding.identity_hash,
            "title": finding.title,
            "desc": f"{finding.title} observed at runtime.",
            "first_seen_time": _millis(finding.first_seen_at),
            "last_seen_time": _millis(finding.last_seen_at),
        },
        "vulnerabilities": [vulnerability],
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Aegis IAST",
                "vendor_name": "Aegis",
                "version": product_version,
            },
        },
        "risk_score": finding.risk_score,
        "unmapped": {
            "rule_key": finding.rule_key,
            "environments": list(finding.environments_seen),
            "occurrence_count": finding.occurrence_count,
            "would_block_count": finding.would_block_count,
        },
    }
    if occurrence is not None:
        event["src_endpoint"] = {"ip": occurrence.remote_address or None}
        event["http_request"] = {
            "http_method": occurrence.request_method or None,
            "url": {"path": occurrence.request_path or None},
        }
    return event


# --- CEF ----------------------------------------------------------------------------

CEF_VERSION = 0


def _cef_header(value: str) -> str:
    """Escape a pipe-delimited header field.

    Backslash first — escaping it after the pipe would double-escape the backslashes this
    function just introduced.
    """
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(value: object) -> str:
    """Escape an extension value.

    ``=`` and newlines are the dangerous ones: both let attacker-controlled content close the
    current field and open another, which is how a forged event or a forged severity gets into
    a SOC's console. Carriage returns are folded too, since some collectors split on either.
    """
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


#: CEF severity runs 0 to 10, and so does our risk score, so no rescaling is needed and what
#: an analyst sorts on is exactly what we computed.
def to_cef(
    finding: Finding,
    occurrence: Occurrence | None,
    *,
    product_version: str,
    max_argument_length: int = 1024,
) -> str:
    """One CEF line."""
    header = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            _cef_header("Aegis"),
            _cef_header("Aegis IAST"),
            _cef_header(product_version),
            _cef_header(finding.rule_key),
            _cef_header(finding.title),
            str(round(finding.risk_score)),
        ]
    )

    extensions: dict[str, object] = {
        "externalId": finding.identity_hash,
        "cat": finding.rule_key,
        "cs1Label": "status",
        "cs1": finding.status.value,
        "cs2Label": "confidence",
        "cs2": finding.confidence.value,
        "cs3Label": "sink",
        "cs3": finding.sink_signature,
        "cs4Label": "sourceKind",
        "cs4": finding.source_kind,
        "cn1Label": "occurrences",
        "cn1": finding.occurrence_count,
        "cn2Label": "wouldBlock",
        "cn2": finding.would_block_count,
    }
    if finding.cwe_id is not None:
        extensions["cs5Label"] = "cwe"
        extensions["cs5"] = f"CWE-{finding.cwe_id}"
    if finding.last_seen_at is not None:
        extensions["end"] = _millis(finding.last_seen_at)
    if finding.environments_seen:
        extensions["deviceCustomString6Label"] = "environments"
        extensions["deviceCustomString6"] = ",".join(finding.environments_seen)

    if occurrence is not None:
        if occurrence.remote_address:
            extensions["src"] = occurrence.remote_address
        if occurrence.request_method:
            extensions["requestMethod"] = occurrence.request_method
        if occurrence.request_path:
            extensions["request"] = occurrence.request_path
        if occurrence.sink_argument:
            # Truncated as well as escaped. A sink argument can be megabytes of attacker input,
            # and a syslog collector that drops oversized lines would lose the whole event.
            extensions["msg"] = occurrence.sink_argument[:max_argument_length]

    body = " ".join(f"{key}={_cef_value(value)}" for key, value in extensions.items())
    return f"{header}|{body}"


class ExportFindingsForSiem:
    """Export findings as OCSF events or CEF lines."""

    MAX_RESULTS = 5000

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        fmt: str,
        application_id: UUID | None = None,
        product_version: str = "0.5.0",
    ) -> tuple[list[dict[str, Any]] | str, str]:
        """:returns: the payload and the media type to serve it as."""
        principal.require(Permission.FINDING_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            findings, _ = await uow.findings.list_all(
                limit=self.MAX_RESULTS, cursor=None, application_id=application_id
            )
            pairs: list[tuple[Finding, Occurrence | None]] = []
            for finding in findings:
                samples = await uow.findings.list_occurrences(finding.id, limit=1)
                pairs.append((finding, samples[0] if samples else None))

        if fmt == "cef":
            lines = [
                to_cef(finding, occurrence, product_version=product_version)
                for finding, occurrence in pairs
            ]
            return "\n".join(lines) + ("\n" if lines else ""), "text/plain; charset=utf-8"
        return [
            to_ocsf(finding, occurrence, product_version=product_version)
            for finding, occurrence in pairs
        ], "application/json"
