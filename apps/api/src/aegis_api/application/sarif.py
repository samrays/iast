"""SARIF 2.1.0 export, so findings reach developers where they already work.

A finding that lives only in our console is a finding somebody has to remember to go and look
at. SARIF is how it turns up in a pull request instead — GitHub code scanning, GitLab, and most
IDEs consume it directly.

Two things about mapping IAST results into SARIF are worth stating, because the impedance
mismatch is real and pretending otherwise would produce a plausible-looking file that behaves
badly:

**SARIF wants a file and a line. We observe runtime dataflow.** There is no source file in a
taint trace — there is a stack frame. The location is therefore *reconstructed* from the
innermost application frame, turning ``com.acme.UserRepository`` into
``com/acme/UserRepository.java``. That is a good guess for JVM layouts and a guess nonetheless,
so it is deliberately not what carries identity.

**Identity travels in ``partialFingerprints``, not in the location.** GitHub uses fingerprints
to decide whether a result in today's run is the same finding as yesterday's. Ours is already
deterministic and already excludes line numbers (ADR-0009), which is exactly the property
fingerprints need — so a reformat that moves every line still resolves to one finding with its
triage history intact. Handing GitHub a line-derived fingerprint would throw that away.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ..domain.entities.findings import Finding, FindingStatus, Occurrence, Severity
from ..domain.permissions import Permission
from ..domain.ports import UnitOfWork
from .context import Principal
from .findings import CWE_BY_RULE, TITLE_BY_RULE

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: SARIF has three levels; we have five severities. Anything a developer should stop for is an
#: error, and the rest degrade rather than being dropped — a note is still visible, and silently
#: discarding low-severity findings on export would misrepresent the scan.
_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: SARIF's own vocabulary for how much to trust a result.
_PRECISION_BY_CONFIDENCE = {
    "EXPLOITED": "very-high",
    "CONFIRMED": "high",
    "SUSPECTED": "medium",
}


def _artifact_uri(declaring_class: str) -> str:
    """``com.acme.UserRepository$Inner`` → ``com/acme/UserRepository.java``.

    Nested and anonymous classes live in their outer class's file, so everything from the first
    ``$`` is dropped. This is a reconstruction, not an observation — see the module docstring.
    """
    outer = declaring_class.split("$", 1)[0]
    return outer.replace(".", "/") + ".java" if outer else "unknown"


def _location(occurrence: Occurrence | None) -> list[dict[str, Any]]:
    if occurrence is None:
        return []
    frame = next((f for f in occurrence.stack_frames if f[3]), None)
    if frame is None:
        return []
    declaring_class, _method, line, _is_app = frame
    region: dict[str, Any] = {}
    if line > 0:
        # startLine is the only part of the region we can honestly fill in. Columns would be
        # fabricated, and a wrong column is worse than none: it points somewhere specific.
        region["startLine"] = line
    physical: dict[str, Any] = {"artifactLocation": {"uri": _artifact_uri(declaring_class)}}
    if region:
        physical["region"] = region
    return [{"physicalLocation": physical}]


def _message(finding: Finding, occurrence: Occurrence | None) -> str:
    """What a developer reads in the pull request.

    It names the source, the sink and the route, because those three answer "why is this here"
    without anyone having to open the console.
    """
    parts = [
        f"{TITLE_BY_RULE.get(finding.rule_key, finding.rule_key)}: "
        f"{finding.source_kind.lower()} data reaches {finding.sink_signature}."
    ]
    if finding.route_templates:
        parts.append(f"Observed on {finding.route_templates[0]}.")
    if finding.environments_seen:
        parts.append(f"Seen in {', '.join(finding.environments_seen)}.")
    if occurrence is not None and occurrence.attack_detected:
        parts.append("An exploitation attempt reached this sink.")
    return " ".join(parts)


def _rule(rule_key: str) -> dict[str, Any]:
    title = TITLE_BY_RULE.get(rule_key, rule_key)
    cwe = CWE_BY_RULE.get(rule_key)
    rule: dict[str, Any] = {
        "id": rule_key,
        "name": title.replace(" ", ""),
        "shortDescription": {"text": title},
        "fullDescription": {
            "text": (
                f"{title} confirmed at runtime: untrusted input was observed reaching a "
                "security-sensitive operation without adequate neutralization."
            )
        },
        "help": {
            "text": (
                "Aegis observed this by tracking the value from where it entered the "
                "application to where it was used. The finding is a real dataflow, not a "
                "pattern match."
            )
        },
        "properties": {"tags": ["security", rule_key]},
    }
    if cwe is not None:
        # GitHub surfaces CWE tags as filters, which is how a security team slices a backlog.
        rule["properties"]["tags"].append(f"external/cwe/cwe-{cwe}")
    return rule


def _suppression(finding: Finding) -> list[dict[str, Any]]:
    """Carry our triage decision across, so a dismissal here is a dismissal there.

    Without this, every suppressed finding reappears in the next pull request and somebody
    re-triages a decision that was already made.
    """
    if not finding.status.is_suppressed:
        return []
    kind = "false-positive" if finding.status is FindingStatus.FALSE_POSITIVE else "external"
    suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
    justification = finding.triage_note or f"Marked {finding.status.value} in Aegis."
    suppression["justification"] = justification
    suppression["properties"] = {"aegisStatus": finding.status.value, "aegisKind": kind}
    return [suppression]


def build_sarif(
    pairs: list[tuple[Finding, Occurrence | None]], *, tool_version: str, tool_uri: str
) -> dict[str, Any]:
    """Assemble the document. Pure — no I/O, so it is testable without a database."""
    rule_keys: list[str] = []
    results: list[dict[str, Any]] = []

    for finding, occurrence in pairs:
        if finding.rule_key not in rule_keys:
            rule_keys.append(finding.rule_key)

        result: dict[str, Any] = {
            "ruleId": finding.rule_key,
            "ruleIndex": rule_keys.index(finding.rule_key),
            "level": _LEVEL_BY_SEVERITY.get(finding.severity, "warning"),
            "message": {"text": _message(finding, occurrence)},
            "locations": _location(occurrence),
            # The deterministic identity from ADR-0009. It excludes line numbers, which is
            # precisely what lets a reformat keep one finding rather than closing it and
            # opening a new one.
            "partialFingerprints": {"aegisIdentityHash/v1": finding.identity_hash},
            "properties": {
                # A string, per the GitHub convention, and 0 to 10, which our risk score already
                # is, so the ordering a developer sees matches the ordering we computed.
                "security-severity": f"{finding.risk_score:.1f}",
                "precision": _PRECISION_BY_CONFIDENCE.get(finding.confidence.value, "medium"),
                "aegisStatus": finding.status.value,
                "aegisOccurrences": finding.occurrence_count,
            },
        }
        if finding.would_block_count:
            result["properties"]["aegisWouldBlock"] = finding.would_block_count
        suppressions = _suppression(finding)
        if suppressions:
            result["suppressions"] = suppressions
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis IAST",
                        "version": tool_version,
                        "informationUri": tool_uri,
                        "rules": [_rule(key) for key in rule_keys],
                    }
                },
                "results": results,
            }
        ],
    }


class ExportFindingsAsSarif:
    """Export the actionable queue as SARIF.

    Suppressed findings are included rather than filtered, carrying their suppression with
    them. Omitting them would make the consumer rediscover each one and ask somebody to triage
    a decision that has already been made.
    """

    #: A pull-request annotation set has to stay readable. Beyond this the export is truncated
    #: rather than refused, worst-first, because a partial report is useful and a 500 is not.
    MAX_RESULTS = 1000

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        application_id: UUID | None = None,
        tool_version: str = "0.5.0",
        tool_uri: str = "https://github.com/aegis-iast",
    ) -> dict[str, Any]:
        principal.require(Permission.FINDING_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            findings, _ = await uow.findings.list_all(
                limit=self.MAX_RESULTS,
                cursor=None,
                application_id=application_id,
            )
            pairs: list[tuple[Finding, Occurrence | None]] = []
            for finding in findings:
                samples = await uow.findings.list_occurrences(finding.id, limit=1)
                pairs.append((finding, samples[0] if samples else None))
            return build_sarif(pairs, tool_version=tool_version, tool_uri=tool_uri)
