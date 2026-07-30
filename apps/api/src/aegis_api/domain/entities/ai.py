"""AI analyses of findings: what a model said, and what a human decided about it.

Three properties shape everything here, and each exists because of a specific way this feature
can hurt someone.

**An analysis is advice, never a fact.** The model explains a finding the engine already
produced; it never creates, closes, scores or suppresses one. A wrong explanation costs a
developer ten minutes. A model allowed to close findings would cost them a breach.

**Nothing is applied without a person.** Every analysis starts as a draft and stays one until
somebody accepts it (ADR-0008). This is not ceremony: a remediation suggestion is a code
change, and an LLM that could commit one is an LLM with write access to production.

**The input is attacker-controlled.** A finding carries the payload that triggered it — that is
its whole purpose — and that payload goes into a prompt. Anyone who can reach the vulnerable
endpoint can therefore write text that a model will read. The mitigations live in
:mod:`aegis_api.application.ai`, but the consequence is recorded on the entity: the exact
prompt is hashed and stored, so a suspicious answer can be traced back to the input that
produced it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from ..errors import InvalidStateError
from ..value_objects import new_id


class AnalysisKind(StrEnum):
    """What was asked of the model."""

    #: Why this finding exists and what an attacker could do with it.
    ROOT_CAUSE = "ROOT_CAUSE"
    #: How to fix it, as a described change rather than a patch to apply.
    REMEDIATION = "REMEDIATION"
    #: Whether the evidence supports the finding at all — the model arguing against us.
    TRIAGE_ASSESSMENT = "TRIAGE_ASSESSMENT"


class AnalysisStatus(StrEnum):
    DRAFT = "DRAFT"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    #: The model declined, or its answer failed validation. Kept rather than discarded so the
    #: failure rate is visible instead of looking like the feature was never used.
    FAILED = "FAILED"


@dataclass(slots=True)
class AiAnalysis:
    """One model response about one finding, and its review state."""

    organization_id: UUID
    finding_id: UUID
    kind: AnalysisKind
    #: The model's answer. Prose for a human, never a command for a machine.
    content: str = ""
    summary: str = ""
    status: AnalysisStatus = AnalysisStatus.DRAFT
    model: str = ""
    #: SHA-256 of the exact prompt sent. Lets a suspicious answer be traced to its input
    #: without storing the attacker's payload a second time.
    prompt_hash: str = ""
    #: Recorded because it is the number that decides whether this feature is affordable.
    input_tokens: int = 0
    output_tokens: int = 0
    reviewed_by: UUID | None = None
    review_note: str = ""
    failure_reason: str = ""
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    reviewed_at: datetime | None = None

    MAX_CONTENT = 20_000

    def __post_init__(self) -> None:
        self.content = (self.content or "")[: self.MAX_CONTENT]
        self.summary = (self.summary or "").strip()[:300]

    @property
    def is_actionable(self) -> bool:
        """Only an accepted analysis may be shown as guidance rather than as a suggestion."""
        return self.status is AnalysisStatus.ACCEPTED

    def accept(self, *, reviewer_id: UUID, now: datetime, note: str = "") -> None:
        self._require_reviewable()
        self.status = AnalysisStatus.ACCEPTED
        self._record_review(reviewer_id, now, note)

    def reject(self, *, reviewer_id: UUID, now: datetime, note: str) -> None:
        """Reject, with a reason.

        The reason is required because rejections are the only signal this feature is wrong.
        A silently discarded answer teaches nobody anything; "hallucinated a method that does
        not exist" is the difference between a prompt that gets fixed and one that does not.
        """
        if not note.strip():
            raise InvalidStateError("Rejecting an analysis requires a reason.")
        self._require_reviewable()
        self.status = AnalysisStatus.REJECTED
        self._record_review(reviewer_id, now, note)

    def fail(self, reason: str) -> None:
        self.status = AnalysisStatus.FAILED
        self.failure_reason = reason.strip()[:500]

    def _require_reviewable(self) -> None:
        if self.status is not AnalysisStatus.DRAFT:
            # Re-reviewing would overwrite who decided and when, which is the part of this
            # record that matters if the advice turns out to be wrong.
            raise InvalidStateError(
                f"An analysis in {self.status.value} has already been reviewed."
            )

    def _record_review(self, reviewer_id: UUID, now: datetime, note: str) -> None:
        self.reviewed_by = reviewer_id
        self.reviewed_at = now
        self.review_note = note.strip()[:2000]


def prompt_fingerprint(prompt: str) -> str:
    """Hash a prompt for the audit trail.

    The prompt rather than the response, and a hash rather than the text: the prompt embeds
    attacker-controlled evidence, and storing it verbatim would duplicate a payload the system
    already holds once, in a table nobody thinks of as containing hostile input.
    """
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()
