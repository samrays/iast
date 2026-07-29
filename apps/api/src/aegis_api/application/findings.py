"""The worker pipeline: runtime events in, managed findings out.

This is where the agent's stream of "a tainted value reached a sink" becomes the thing a
developer actually works from. The pipeline is short and each step earns its place:

    resolve tenant and application → build identity → upsert finding → record evidence → score

Two properties govern the design.

**Idempotence.** The gateway's transport is at-least-once and its spool replays after an
outage, so the same event will arrive twice. Every step here is safe to repeat: identity is
derived, not assigned, and the unique constraint on ``(organization_id, identity_hash)`` is
what turns a repeated event into an increment rather than a second row.

**Tenant attribution comes from the envelope, never the payload.** The gateway stamped the
organization and agent from a verified credential. Anything inside ``payload`` was written by
code running in the customer's process, which an attacker may control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from ..domain.entities.audit import AuditAction
from ..domain.entities.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Occurrence,
    Severity,
    finding_identity,
    score_finding,
    stack_fingerprint,
)
from ..domain.entities.inventory import Criticality, EnvironmentKind
from ..domain.errors import NotFoundError, ValidationError
from ..domain.permissions import Permission
from ..domain.ports import UnitOfWork
from .audit_recorder import AuditRecorder
from .context import Principal
from .dto import Page

#: Rule keys the agent emits, mapped to the CWE a report needs to cite.
CWE_BY_RULE: dict[str, int] = {
    "sql-injection": 89,
    "command-injection": 78,
    "path-traversal": 22,
    "unsafe-deserialization": 502,
    "reflected-xss": 79,
    "ssrf": 918,
    "ldap-injection": 90,
    "xpath-injection": 643,
    "open-redirect": 601,
    "log-injection": 117,
    "header-injection": 113,
}

#: Human titles. A finding list that reads `sql-injection` in every row is a list nobody scans.
TITLE_BY_RULE: dict[str, str] = {
    "sql-injection": "SQL injection",
    "command-injection": "OS command injection",
    "path-traversal": "Path traversal",
    "unsafe-deserialization": "Unsafe deserialization",
    "reflected-xss": "Reflected cross-site scripting",
    "ssrf": "Server-side request forgery",
    "ldap-injection": "LDAP injection",
    "xpath-injection": "XPath injection",
    "open-redirect": "Open redirect",
    "log-injection": "Log injection",
    "header-injection": "HTTP header injection",
}


class EventRejectedError(Exception):
    """The event cannot become a finding, and never will. Acknowledge and move on.

    Distinct from a transient failure on purpose: a malformed event retried forever would
    block the stream behind it, and a stalled worker is indistinguishable from an application
    with no vulnerabilities.
    """


@dataclass(slots=True)
class ProcessingResult:
    findings_created: int = 0
    findings_updated: int = 0
    regressions: int = 0
    occurrences_stored: int = 0
    rejected: int = 0
    ignored: int = 0
    rejections: list[str] = field(default_factory=list)

    @property
    def processed(self) -> int:
        return self.findings_created + self.findings_updated


@dataclass(slots=True)
class AgentContext:
    """Where an agent's telemetry belongs, resolved once per agent."""

    application_id: UUID
    environment_kind: EnvironmentKind
    internet_facing: bool
    criticality: Criticality

    @property
    def exposure_weight(self) -> float:
        base = {
            EnvironmentKind.DEVELOPMENT: 0.3,
            EnvironmentKind.QA: 0.4,
            EnvironmentKind.STAGING: 0.7,
            EnvironmentKind.PRODUCTION: 1.0,
        }[self.environment_kind]
        return base * (1.3 if self.internet_facing else 1.0)


class ProcessRuntimeEvents:
    """Fold a batch of runtime events into findings.

    :param evidence_interval: how often a fresh evidence sample is kept for one finding. A
        finding hit a million times does not need a million near-identical traces; keeping
        one an hour bounds the storage a single hot endpoint can consume without losing the
        ability to show a developer a concrete example.
    """

    def __init__(
        self,
        *,
        uow_factory: Any,
        evidence_interval: timedelta = timedelta(hours=1),
    ) -> None:
        self._uow_factory = uow_factory
        self._evidence_interval = evidence_interval

    async def execute(self, records: list[dict[str, Any]]) -> ProcessingResult:
        result = ProcessingResult()

        # Grouped by tenant so one transaction — and one RLS binding — covers a run of events
        # from the same organization, rather than one round trip per event.
        for organization_id, batch in _group_by_tenant(records, result).items():
            async with self._uow_factory() as uow:
                await uow.bind_tenant(organization_id)
                contexts: dict[str, AgentContext | None] = {}
                for record in batch:
                    try:
                        await self._apply(uow, organization_id, record, contexts, result)
                    except EventRejectedError as rejection:
                        result.rejected += 1
                        if len(result.rejections) < 50:
                            result.rejections.append(str(rejection))
                await uow.commit()
        return result

    async def _apply(
        self,
        uow: Any,
        organization_id: UUID,
        record: dict[str, Any],
        contexts: dict[str, AgentContext | None],
        result: ProcessingResult,
    ) -> None:
        if record.get("type") != "EVENT_TYPE_TAINT_HIT":
            # Routes, coverage gaps and heartbeats are handled by their own consumers. The
            # finding pipeline reads only what can become a finding.
            result.ignored += 1
            return

        agent_id = str(record.get("agent_id") or "")
        if not agent_id:
            raise EventRejectedError(
                "event carries no agent id; cannot attribute it to an application"
            )

        if agent_id not in contexts:
            contexts[agent_id] = await uow.findings.resolve_agent_context(agent_id)
        context = contexts[agent_id]
        if context is None:
            # An agent the control plane has never registered. Refusing is the safe answer:
            # accepting would let anything holding a token invent an application.
            raise EventRejectedError(f"agent {agent_id} is not registered")

        # The gateway unwraps the agent's `taint_hit` object into `payload` — the envelope's
        # `type` already says what the payload is, so nesting it again would be redundant.
        # Reading one level too deep here cost a live end-to-end run to find, because the test
        # fixtures were written from the same wrong assumption and agreed with it.
        hit = record.get("payload")
        if not isinstance(hit, dict) or "sink_signature" not in hit:
            raise EventRejectedError("taint hit event carries no usable payload")

        rule_key = str(hit.get("rule_key") or "").strip().lower()
        if rule_key not in TITLE_BY_RULE:
            raise EventRejectedError(f"unknown rule key {rule_key!r}")

        frames = _frames(hit.get("stack", []))
        source_kind = _primary_source_kind(hit.get("ranges", []))
        stack_hash = stack_fingerprint(frames)
        identity = finding_identity(
            organization_id=organization_id,
            application_id=context.application_id,
            rule_key=rule_key,
            sink_signature=str(hit.get("sink_signature") or ""),
            source_kind=source_kind,
            stack_hash=stack_hash,
        )

        observed_at = _observed_at(record)
        finding = await uow.findings.get_by_identity(identity)
        created = finding is None

        if finding is None:
            finding = Finding(
                organization_id=organization_id,
                application_id=context.application_id,
                identity_hash=identity,
                rule_key=rule_key,
                title=_title(rule_key, frames),
                severity=_severity(hit.get("severity")),
                confidence=_confidence(hit.get("confidence")),
                sink_signature=str(hit.get("sink_signature") or "")[:400],
                source_kind=source_kind,
                stack_hash=stack_hash,
                cwe_id=CWE_BY_RULE.get(rule_key),
            )
        else:
            # An agent upgrade can raise confidence on a defect already known — a suspected
            # flow becomes a confirmed one. Never lower it: losing a confirmation because one
            # request happened to take a less complete path would make the queue flap.
            confidence = _confidence(hit.get("confidence"))
            if _CONFIDENCE_ORDER[confidence] > _CONFIDENCE_ORDER[finding.confidence]:
                finding.confidence = confidence

        regressed = finding.record_occurrence(
            environment=context.environment_kind.value,
            route_template=_route_template(hit),
            observed_at=observed_at,
        )
        if regressed:
            result.regressions += 1

        finding.rescore(
            score_finding(
                severity=finding.severity,
                confidence=finding.confidence,
                exposure_weight=context.exposure_weight,
                criticality_weight=context.criticality.weight,
                attack_observed=finding.confidence is Confidence.EXPLOITED,
                occurrence_count=finding.occurrence_count,
            )
        )
        await uow.findings.upsert(finding)

        if created:
            result.findings_created += 1
        else:
            result.findings_updated += 1

        if await self._should_keep_evidence(uow, finding, observed_at):
            await uow.findings.add_occurrence(
                Occurrence(
                    organization_id=organization_id,
                    finding_id=finding.id,
                    environment=context.environment_kind.value,
                    trace_id=str(record.get("trace_id") or "")[:64],
                    request_method=str(hit.get("request", {}).get("method") or "")[:10],
                    request_path=str(hit.get("request", {}).get("path") or "")[:500],
                    route_template=_route_template(hit),
                    sink_argument=str(hit.get("sink_argument") or ""),
                    tainted_ranges=tuple(_ranges(hit.get("ranges", []))),
                    stack_frames=tuple(_stack_frames(hit.get("stack", []))),
                    remote_address=str(hit.get("request", {}).get("remote_addr") or ""),
                    attack_detected=_confidence(hit.get("confidence")) is Confidence.EXPLOITED,
                    observed_at=observed_at,
                )
            )
            result.occurrences_stored += 1

    async def _should_keep_evidence(
        self, uow: Any, finding: Finding, observed_at: datetime
    ) -> bool:
        """One sample per finding per interval — plus always the first."""
        if finding.occurrence_count <= 1:
            return True
        latest = await uow.findings.latest_occurrence_at(finding.id)
        return latest is None or observed_at - latest >= self._evidence_interval


_CONFIDENCE_ORDER = {
    Confidence.SUSPECTED: 0,
    Confidence.CONFIRMED: 1,
    Confidence.EXPLOITED: 2,
}


def _group_by_tenant(
    records: list[dict[str, Any]], result: ProcessingResult
) -> dict[UUID, list[dict[str, Any]]]:
    grouped: dict[UUID, list[dict[str, Any]]] = {}
    for record in records:
        raw = record.get("organization_id")
        try:
            organization_id = UUID(str(raw))
        except (ValueError, TypeError):
            # The gateway stamps this from a verified credential, so a malformed value means
            # a corrupt stream rather than a hostile agent. Either way it cannot be attributed.
            result.rejected += 1
            if len(result.rejections) < 50:
                result.rejections.append(f"unusable organization id {raw!r}")
            continue
        grouped.setdefault(organization_id, []).append(record)
    return grouped


def _observed_at(record: dict[str, Any]) -> datetime:
    try:
        millis = int(record.get("occurred_at_ms") or 0)
    except (TypeError, ValueError):
        millis = 0
    if millis <= 0:
        return datetime.now(UTC)
    return datetime.fromtimestamp(millis / 1000, tz=UTC)


def _severity(raw: Any) -> Severity:
    value = str(raw or "").removeprefix("SEVERITY_").upper()
    try:
        return Severity(value)
    except ValueError:
        return Severity.MEDIUM


def _confidence(raw: Any) -> Confidence:
    value = str(raw or "").removeprefix("CONFIDENCE_").upper()
    try:
        return Confidence(value)
    except ValueError:
        return Confidence.SUSPECTED


def _primary_source_kind(ranges: Any) -> str:
    """The source kind identity is keyed on.

    The first range, because it is where the attacker's data entered. A value assembled from
    a parameter and a header is one defect on the parameter path, not two.
    """
    if isinstance(ranges, list) and ranges and isinstance(ranges[0], dict):
        return str(ranges[0].get("source") or "").removeprefix("SOURCE_KIND_").upper() or "UNKNOWN"
    return "UNKNOWN"


def _frames(stack: Any) -> list[tuple[str, str, bool]]:
    if not isinstance(stack, list):
        return []
    return [
        (
            str(frame.get("declaring_class") or ""),
            str(frame.get("method_name") or ""),
            bool(frame.get("application_code")),
        )
        for frame in stack
        if isinstance(frame, dict)
    ]


def _stack_frames(stack: Any) -> list[tuple[str, str, int, bool]]:
    if not isinstance(stack, list):
        return []
    return [
        (
            str(frame.get("declaring_class") or ""),
            str(frame.get("method_name") or ""),
            int(frame.get("line_number") or 0),
            bool(frame.get("application_code")),
        )
        for frame in stack
        if isinstance(frame, dict)
    ]


def _ranges(ranges: Any) -> list[tuple[int, int, str, str]]:
    if not isinstance(ranges, list):
        return []
    return [
        (
            int(item.get("start") or 0),
            int(item.get("length") or 0),
            str(item.get("source") or ""),
            str(item.get("source_name") or ""),
        )
        for item in ranges
        if isinstance(item, dict)
    ]


def _route_template(hit: dict[str, Any]) -> str:
    request = hit.get("request", {})
    if not isinstance(request, dict):
        return ""
    return str(request.get("route_template") or request.get("path") or "")[:500]


def _title(rule_key: str, frames: list[tuple[str, str, bool]]) -> str:
    """``SQL injection in UserRepository.findByName``, or just the rule when we cannot say.

    Naming the method is what makes a list scannable. Without it every row of a hundred reads
    identically and the developer has to open each one to find out where it is.
    """
    label = TITLE_BY_RULE.get(rule_key, rule_key)
    for declaring_class, method, is_application in frames:
        if is_application and declaring_class:
            simple = declaring_class.rsplit(".", 1)[-1]
            return f"{label} in {simple}.{method}"[:200]
    return label


# --- Read and triage use cases ---------------------------------------------------------


class ListFindings:
    """The queue a developer opens in the morning.

    Ordered by risk score descending by default, which is the whole reason the score exists:
    a list that is not sorted by what will hurt most gets worked top-to-bottom by accident of
    insertion order.
    """

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        limit: int,
        cursor: str | None,
        status: list[str] | None = None,
        severity: list[str] | None = None,
        rule_key: str | None = None,
        application_id: UUID | None = None,
        environment: str | None = None,
        search: str | None = None,
    ) -> Page[Finding]:
        principal.require(Permission.FINDING_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            items, next_cursor = await uow.findings.list_all(
                limit=limit,
                cursor=cursor,
                statuses=[s.upper() for s in status] if status else None,
                severities=[s.upper() for s in severity] if severity else None,
                rule_key=rule_key,
                application_id=application_id,
                environment=environment.upper() if environment else None,
                search=search,
            )
            return Page(items=items, next_cursor=next_cursor, limit=limit)


class GetFinding:
    """One finding with the evidence a developer needs to reproduce it."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, finding_id: UUID
    ) -> tuple[Finding, list[Occurrence], list[dict[str, Any]]]:
        principal.require(Permission.FINDING_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            finding = await uow.findings.get(finding_id)
            if finding is None:
                raise NotFoundError("Finding not found.")
            occurrences = await uow.findings.list_occurrences(finding_id)
            comments = await uow.findings.list_comments(finding_id)
            return finding, occurrences, comments


class TriageFinding:
    """Move a finding through its lifecycle, and write down who decided and why."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        finding_id: UUID,
        status: FindingStatus,
        note: str = "",
        accepted_for_days: int | None = None,
    ) -> Finding:
        # Suppressing is a stronger act than triaging: it takes a live vulnerability out of
        # everyone's queue, so it carries its own permission rather than riding on triage.
        principal.require(
            Permission.FINDING_SUPPRESS if status.is_suppressed else Permission.FINDING_TRIAGE
        )
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            finding = await uow.findings.get(finding_id)
            if finding is None:
                raise NotFoundError("Finding not found.")

            previous = finding.status
            finding.transition(
                status,
                actor_id=principal.user_id or uuid4(),
                now=datetime.now(UTC),
                note=note,
                accepted_for=timedelta(days=accepted_for_days) if accepted_for_days else None,
            )
            await uow.findings.upsert(finding)
            # Recorded twice on purpose. The audit log answers "who changed what" for a
            # compliance reviewer; the comment thread answers "why" for the next developer who
            # opens this finding and wonders who decided it was acceptable.
            await uow.findings.add_comment(
                finding_id=finding.id,
                organization_id=principal.organization_id,
                author_id=principal.user_id,
                author_label=principal.label,
                body=note or f"Status changed to {status.value}.",
                status_from=previous.value,
                status_to=status.value,
            )
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.FINDING_TRIAGED.value,
                resource_type="finding",
                resource_id=finding.id,
                metadata={
                    "from": previous.value,
                    "to": status.value,
                    "rule_key": finding.rule_key,
                },
            )
            await uow.commit()
            return finding


class CommentOnFinding:
    """Add to the triage thread without changing the finding's state."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal, finding_id: UUID, body: str) -> dict[str, Any]:
        principal.require(Permission.FINDING_TRIAGE)
        text = body.strip()
        if not text:
            raise ValidationError("A comment cannot be empty.")
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            if await uow.findings.get(finding_id) is None:
                raise NotFoundError("Finding not found.")
            comment = await uow.findings.add_comment(
                finding_id=finding_id,
                organization_id=principal.organization_id,
                author_id=principal.user_id,
                author_label=principal.label,
                body=text[:4000],
            )
            await uow.commit()
            return comment


class ExpireAcceptedRisks:
    """Return findings whose accepted-risk window has closed to the open queue.

    Run on a schedule. A risk accepted once, forever, silently is how a finding leaves a
    queue and comes back as an incident.
    """

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, organization_id: UUID) -> int:
        now = datetime.now(UTC)
        async with self._uow as uow:
            await uow.bind_tenant(organization_id)
            expired = 0
            for finding in await uow.findings.list_expired_acceptances(now):
                if finding.expire_acceptance(now):
                    await uow.findings.upsert(finding)
                    await uow.findings.add_comment(
                        finding_id=finding.id,
                        organization_id=organization_id,
                        author_id=None,
                        author_label="system",
                        body="Accepted-risk window expired; returned to the open queue.",
                        status_from=FindingStatus.ACCEPTED_RISK.value,
                        status_to=FindingStatus.OPEN.value,
                    )
                    expired += 1
            await uow.commit()
            return expired
