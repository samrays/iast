"""Findings: the managed, scored, triageable record of a vulnerability.

A :class:`Finding` is a *defect*, not an event. The agent reports the same flaw thousands of
times — once per request that reaches the sink — and every one of those is an
:class:`Occurrence` of a single finding. Getting that collapse right is what separates a
security product from a log: a developer fixes one line of code, and one row closes.

Identity is deterministic and computed here rather than assigned by the database, per ADR-0009.
The same event stream replayed must always produce the same finding set, or replay, audit and
restart all become guesswork.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from ..errors import InvalidStateError
from ..value_objects import new_id


class FindingStatus(StrEnum):
    """Where a finding sits in its lifecycle.

    ``REMEDIATED`` is a claim about the code; ``ACCEPTED_RISK`` and ``FALSE_POSITIVE`` are
    claims about the finding. The distinction matters because only the first should reopen
    when the flaw recurs — a suppression that silently reopened would erase the decision
    someone deliberately made.
    """

    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"

    @property
    def is_suppressed(self) -> bool:
        """Suppressed findings absorb recurrences instead of reopening."""
        return self in (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK)

    @property
    def is_actionable(self) -> bool:
        return self in (FindingStatus.OPEN, FindingStatus.CONFIRMED)


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def base_score(self) -> float:
        return {"INFO": 1.0, "LOW": 3.0, "MEDIUM": 5.0, "HIGH": 7.5, "CRITICAL": 9.0}[self.value]


class Confidence(StrEnum):
    """How sure the agent is that this is real.

    ``EXPLOITED`` means the agent saw an attack payload arrive at the sink — not that it
    inferred one could. That distinction is what makes it safe to drive blocking from.
    """

    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    EXPLOITED = "EXPLOITED"

    @property
    def multiplier(self) -> float:
        return {"SUSPECTED": 0.7, "CONFIRMED": 1.0, "EXPLOITED": 1.2}[self.value]


# Only these transitions are legal. Everything else is rejected rather than silently applied,
# because a triage history that cannot be trusted is worse than none.
_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.REMEDIATED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        }
    ),
    FindingStatus.CONFIRMED: frozenset(
        {
            FindingStatus.REMEDIATED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        }
    ),
    # A remediated finding may be reopened by a human who does not believe the fix, and is
    # reopened automatically by the worker when the flaw recurs.
    FindingStatus.REMEDIATED: frozenset({FindingStatus.OPEN, FindingStatus.CONFIRMED}),
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.OPEN}),
    FindingStatus.ACCEPTED_RISK: frozenset({FindingStatus.OPEN}),
}


def stack_fingerprint(frames: list[tuple[str, str, bool]], depth: int = 1) -> str:
    """Hash the application's own call path to the sink (ADR-0009).

    :param frames: ``(declaring_class, method_name, is_application_code)`` in call order,
        innermost first, exactly as the agent captured them.

    Only the **innermost** application frame counts, per ADR-0012. That is the line the developer
    edits — the concatenation, the ``exec``, the file open — and frames above it describe how it was
    reached, which is context worth showing and wrong to put in identity. Hashing five frames, as
    ADR-0009 originally specified, split one vulnerable line across a finding per call path: the
    developer fixed the line and watched the other rows stay open.

    Framework and standard-library frames are dropped, and **line numbers never reach this
    function at all**. Including them would resurrect every finding on the next reformat and
    orphan its triage history — which teaches a team to ignore the tool, the one outcome no
    security product survives.
    """
    application_frames = [
        f"{declaring_class}#{method}" for declaring_class, method, is_app in frames if is_app
    ]
    return hashlib.sha256("|".join(application_frames[:depth]).encode()).hexdigest()


def finding_identity(
    *,
    organization_id: UUID,
    application_id: UUID,
    rule_key: str,
    sink_signature: str,
    source_kind: str,
    stack_hash: str,
) -> str:
    """The deterministic identity of a defect (ADR-0009).

    Keyed on the **application**, not the environment: the same flaw in staging and production
    is one flaw, and a developer fixing it should see one row close rather than two.

    Nothing attacker-controlled is included. Deriving identity from payload content would let
    an attacker mint unlimited findings by varying their input — a denial-of-service against
    our own data model.
    """
    parts = [
        str(organization_id),
        str(application_id),
        rule_key.strip().lower(),
        _normalize_signature(sink_signature),
        source_kind.strip().upper(),
        stack_hash,
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _normalize_signature(signature: str) -> str:
    """Strip whitespace and any trailing line reference from a sink signature."""
    normalized = " ".join(signature.split())
    return normalized.split(":")[0].strip().lower()


@dataclass(slots=True)
class RiskScore:
    """A score with its reasoning attached.

    The breakdown is not decoration. A number a developer cannot interrogate is a number they
    will argue with instead of act on, so every factor that moved the score is recorded with
    the weight it contributed.
    """

    value: float
    factors: tuple[tuple[str, float, str], ...] = ()

    @property
    def band(self) -> Severity:
        if self.value >= 9.0:
            return Severity.CRITICAL
        if self.value >= 7.0:
            return Severity.HIGH
        if self.value >= 4.0:
            return Severity.MEDIUM
        if self.value >= 1.0:
            return Severity.LOW
        return Severity.INFO


def score_finding(
    *,
    severity: Severity,
    confidence: Confidence,
    exposure_weight: float,
    criticality_weight: float,
    attack_observed: bool,
    occurrence_count: int,
) -> RiskScore:
    """Combine the factors that decide what gets fixed first.

    Ordering, not arithmetic precision, is the product requirement: a queue sorted by this
    number has to put the thing that will actually hurt the customer at the top. Occurrence
    count deliberately contributes very little — a flaw on a hot endpoint is not more broken
    than the same flaw on a rare one, and letting traffic dominate would bury a critical
    defect on an admin page under a medium one on a landing page.
    """
    factors: list[tuple[str, float, str]] = []

    base = severity.base_score
    factors.append(("severity", base, f"{severity.value} rule class"))

    score = base * confidence.multiplier
    factors.append(
        (
            "confidence",
            score - base,
            f"{confidence.value}: "
            + (
                "an attack payload reached the sink"
                if confidence is Confidence.EXPLOITED
                else (
                    "dataflow confirmed from source to sink"
                    if confidence is Confidence.CONFIRMED
                    else "dataflow incomplete or imprecise"
                )
            ),
        )
    )

    before = score
    score *= exposure_weight
    factors.append(("exposure", score - before, f"environment weight {exposure_weight:.2f}"))

    before = score
    score *= criticality_weight
    factors.append(
        ("business criticality", score - before, f"application weight {criticality_weight:.2f}")
    )

    if attack_observed:
        before = score
        score += 1.0
        factors.append(("active attack", score - before, "exploitation attempts observed"))

    if occurrence_count > 1:
        before = score
        # Logarithmic and capped, so volume nudges the ordering without ever deciding it.
        score += min(0.5, 0.1 * (occurrence_count.bit_length() - 1))
        factors.append(("recurrence", score - before, f"{occurrence_count} occurrences"))

    return RiskScore(value=round(min(score, 10.0), 2), factors=tuple(factors))


@dataclass(slots=True)
class Finding:
    """One defect in one application."""

    organization_id: UUID
    application_id: UUID
    identity_hash: str
    rule_key: str
    title: str
    severity: Severity
    confidence: Confidence
    sink_signature: str
    source_kind: str
    stack_hash: str
    status: FindingStatus = FindingStatus.OPEN
    risk_score: float = 0.0
    risk_factors: tuple[tuple[str, float, str], ...] = ()
    occurrence_count: int = 0
    suppressed_occurrence_count: int = 0
    environments_seen: tuple[str, ...] = ()
    route_templates: tuple[str, ...] = ()
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    remediated_at: datetime | None = None
    regressed: bool = False
    accepted_until: datetime | None = None
    triage_note: str = ""
    triaged_by: UUID | None = None
    cwe_id: int | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    #: Distinct routes remembered per finding, so one flaw reachable from many endpoints stays
    #: one finding without the list growing without bound.
    MAX_ROUTES = 20

    def __post_init__(self) -> None:
        self.title = (self.title or "").strip()[:200]
        if not self.title:
            raise InvalidStateError("A finding must have a title.")
        if not self.identity_hash:
            raise InvalidStateError("A finding must have an identity hash.")

    # --- ingest ----------------------------------------------------------------------

    def record_occurrence(
        self, *, environment: str, route_template: str, observed_at: datetime
    ) -> bool:
        """Fold a repeat sighting into this finding.

        :returns: True when the finding reopened as a regression.

        A suppressed finding counts the recurrence separately and does **not** reopen. That
        number is the point: it lets someone see that an accepted risk is still absorbing live
        traffic, and revisit the decision with evidence rather than rediscover the flaw.
        """
        self.last_seen_at = observed_at
        if self.first_seen_at is None:
            self.first_seen_at = observed_at

        if environment and environment not in self.environments_seen:
            self.environments_seen = (*self.environments_seen, environment)
        if route_template and route_template not in self.route_templates:
            self.route_templates = (*self.route_templates, route_template)[: self.MAX_ROUTES]

        if self.status.is_suppressed:
            self.suppressed_occurrence_count += 1
            return False

        self.occurrence_count += 1

        if self.status is FindingStatus.REMEDIATED:
            # The fix did not hold, or was never deployed. Reopening with a flag distinguishes
            # this from a defect that was never addressed — a team's second attempt at the same
            # bug deserves to be visible.
            self.status = FindingStatus.OPEN
            self.regressed = True
            self.remediated_at = None
            return True
        return False

    def rescore(self, score: RiskScore) -> None:
        self.risk_score = score.value
        self.risk_factors = score.factors

    # --- triage ----------------------------------------------------------------------

    def transition(
        self,
        target: FindingStatus,
        *,
        actor_id: UUID,
        now: datetime,
        note: str = "",
        accepted_for: timedelta | None = None,
    ) -> None:
        """Move the finding through its lifecycle, or refuse.

        Suppressing a finding requires a note. Someone will read it in six months trying to
        work out why a live vulnerability is marked as accepted, and "no reason given" is not
        an answer anyone can act on.
        """
        if target is self.status:
            return
        if target not in _ALLOWED_TRANSITIONS[self.status]:
            raise InvalidStateError(
                f"A finding cannot move from {self.status.value} to {target.value}."
            )
        if target.is_suppressed and not note.strip():
            raise InvalidStateError(f"Marking a finding {target.value} requires a reason.")

        self.status = target
        self.triaged_by = actor_id
        self.triage_note = note.strip()[:2000]

        if target is FindingStatus.REMEDIATED:
            self.remediated_at = now
            self.regressed = False
        else:
            self.remediated_at = None

        if target is FindingStatus.ACCEPTED_RISK:
            # Acceptance expires. A risk accepted once, forever, silently, is how a finding
            # disappears from a queue and reappears in an incident.
            self.accepted_until = now + (accepted_for or timedelta(days=90))
        else:
            self.accepted_until = None

    def expire_acceptance(self, now: datetime) -> bool:
        """Return an expired acceptance to the queue. Called by the sweeper."""
        if (
            self.status is FindingStatus.ACCEPTED_RISK
            and self.accepted_until is not None
            and self.accepted_until <= now
        ):
            self.status = FindingStatus.OPEN
            self.accepted_until = None
            return True
        return False

    @property
    def is_open_in_production(self) -> bool:
        return self.status.is_actionable and "PRODUCTION" in self.environments_seen


@dataclass(slots=True)
class Occurrence:
    """One observed sighting of a finding, with the evidence attached.

    Stored sparsely. A finding hit a million times does not need a million copies of nearly
    identical evidence — the worker rate-limits samples, so what is kept is a handful of
    representative traces rather than a transcript of production traffic.
    """

    organization_id: UUID
    finding_id: UUID
    environment: str
    trace_id: str
    request_method: str
    request_path: str
    route_template: str
    sink_argument: str
    tainted_ranges: tuple[tuple[int, int, str, str], ...]
    stack_frames: tuple[tuple[str, str, int, bool], ...]
    remote_address: str = ""
    attack_detected: bool = False
    observed_at: datetime | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
