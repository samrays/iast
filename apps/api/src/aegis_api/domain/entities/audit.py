"""The audit log — append-only and tamper-evident.

Each entry hashes its predecessor, so removing or altering an entry breaks the chain from
that point onward and the nightly verification job detects it (threat T-11). The database
role used by the application has no ``UPDATE`` or ``DELETE`` grant on this table.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from ..value_objects import new_id

#: The genesis link for an organization's chain.
GENESIS_HASH = "0" * 64


class AuditOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class ActorType(StrEnum):
    USER = "USER"
    API_KEY = "API_KEY"
    AGENT = "AGENT"
    SYSTEM = "SYSTEM"


class AuditAction(StrEnum):
    """Actions worth recording.

    Reads are not audited by default — the volume would drown the signal. Reads of the
    audit log itself, and of secrets, are the exceptions.
    """

    # Authentication
    LOGIN_SUCCEEDED = "auth.login_succeeded"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password_changed"
    PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password_reset_completed"
    MFA_ENROLLED = "auth.mfa_enrolled"
    MFA_DISABLED = "auth.mfa_disabled"
    MFA_CHALLENGE_FAILED = "auth.mfa_challenge_failed"
    ACCOUNT_LOCKED = "auth.account_locked"
    TOKEN_REFRESHED = "auth.token_refreshed"
    TOKEN_REUSE_DETECTED = "security.token_reuse"
    SESSION_REVOKED = "auth.session_revoked"

    # Tenancy and access
    ORGANIZATION_CREATED = "org.created"
    ORGANIZATION_UPDATED = "org.updated"
    MEMBER_INVITED = "member.invited"
    MEMBER_ROLES_CHANGED = "member.roles_changed"
    MEMBER_REMOVED = "member.removed"
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"
    PRIVILEGE_ESCALATION_BLOCKED = "security.privilege_escalation_blocked"

    # Credentials
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"

    # Inventory and fleet
    APPLICATION_CREATED = "application.created"
    APPLICATION_UPDATED = "application.updated"
    APPLICATION_DELETED = "application.deleted"
    ENVIRONMENT_CREATED = "environment.created"
    PROTECTION_MODE_CHANGED = "environment.protection_mode_changed"
    AGENT_REGISTERED = "agent.registered"
    AGENT_UPDATED = "agent.updated"

    # Findings
    FINDING_TRIAGED = "finding.triaged"

    # Detection policy
    RULE_TOGGLED = "rule.toggled"

    # Governance
    AUDIT_LOG_READ = "audit.read"
    PERMISSION_DENIED = "security.permission_denied"


@dataclass(slots=True)
class AuditEvent:
    """One immutable entry in an organization's audit chain."""

    organization_id: UUID
    action: str
    actor_type: ActorType = ActorType.SYSTEM
    actor_user_id: UUID | None = None
    actor_label: str = ""
    resource_type: str = ""
    resource_id: str = ""
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    ip_address: str | None = None
    user_agent: str = ""
    request_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""
    occurred_at: datetime | None = None
    sequence: int = 0
    id: UUID = field(default_factory=new_id)

    def seal(self, previous_hash: str, occurred_at: datetime, sequence: int) -> None:
        """Link this entry into the chain and compute its hash.

        Called once, by the repository, inside the same transaction that assigns the
        sequence number — so two concurrent writers cannot both claim the same link.
        """
        self.previous_hash = previous_hash
        self.occurred_at = occurred_at
        self.sequence = sequence
        self.entry_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Deterministic digest over every field that must not change silently."""
        payload = {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "sequence": self.sequence,
            "action": self.action,
            "actor_type": self.actor_type.value,
            "actor_user_id": str(self.actor_user_id) if self.actor_user_id else None,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "outcome": self.outcome.value,
            "ip_address": self.ip_address,
            "metadata": self.metadata,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "previous_hash": self.previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify(self, expected_previous_hash: str) -> bool:
        """True when this entry links correctly and its own contents are unaltered."""
        return (
            self.previous_hash == expected_previous_hash and self.entry_hash == self.compute_hash()
        )
