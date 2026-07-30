"""SQLAlchemy models.

These are persistence records, not domain objects. Repositories translate between the two,
which is what allows the domain to stay free of SQLAlchemy (ADR-0002) and allows the schema
to change without rewriting business rules.

Every tenant-owned table carries ``organization_id`` as the leading column of its primary
access index, so the mandatory tenant predicate and the row-level-security policy both ride
the same B-tree (ADR-0003).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

# --- Enumerations -------------------------------------------------------------------
#
# Stored as TEXT with a CHECK constraint rather than a native PostgreSQL ENUM. Adding a
# value to a native enum requires ALTER TYPE, which does not roll back inside a
# transaction and complicates zero-downtime deploys; a CHECK constraint is a plain,
# reversible DDL change.

_ORG_STATUSES = ("ACTIVE", "SUSPENDED", "PENDING_DELETION")
_USER_STATUSES = ("ACTIVE", "INVITED", "DISABLED")
_MEMBERSHIP_STATUSES = ("ACTIVE", "INVITED", "SUSPENDED")
_MFA_KINDS = ("TOTP", "RECOVERY_CODE")
_LICENSE_TIERS = ("TRIAL", "TEAM", "BUSINESS", "ENTERPRISE")
_LANGUAGES = ("JAVA", "DOTNET", "NODE", "PYTHON", "GO")
_CRITICALITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_ENVIRONMENT_KINDS = ("DEVELOPMENT", "QA", "STAGING", "PRODUCTION")
_PROTECTION_MODES = ("OFF", "MONITOR", "BLOCK")
_AGENT_STATUSES = ("REGISTERED", "ONLINE", "DEGRADED", "OFFLINE", "DISABLED")
_AUDIT_OUTCOMES = ("SUCCESS", "FAILURE", "DENIED")
_ACTOR_TYPES = ("USER", "API_KEY", "AGENT", "SYSTEM")
_FINDING_STATUSES = ("OPEN", "CONFIRMED", "REMEDIATED", "FALSE_POSITIVE", "ACCEPTED_RISK")
_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_CONFIDENCES = ("SUSPECTED", "CONFIRMED", "EXPLOITED")


def _enum_check(column: str, values: tuple[str, ...], name: str) -> CheckConstraint:
    rendered = ", ".join(f"'{v}'" for v in values)
    return CheckConstraint(f"{column} IN ({rendered})", name=name)


# --- Tenancy ------------------------------------------------------------------------


class OrganizationRecord(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    deletion_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        _enum_check("status", _ORG_STATUSES, "organizations_status"),
        Index("ix_organizations_status", "status"),
    )


class LicenseRecord(Base, TimestampMixin):
    __tablename__ = "licenses"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    tier: Mapped[str] = mapped_column(
        String(20), nullable=False, default="TRIAL", server_default="TRIAL"
    )
    max_applications: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, server_default="3"
    )
    max_agents: Mapped[int] = mapped_column(Integer, nullable=False, default=5, server_default="5")
    max_users: Mapped[int] = mapped_column(Integer, nullable=False, default=5, server_default="5")
    ai_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    protection_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (_enum_check("tier", _LICENSE_TIERS, "licenses_tier"),)


# --- Identity -----------------------------------------------------------------------


class UserRecord(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    # CITEXT so uniqueness is genuinely case-insensitive at the database level, not merely
    # by application convention.
    email: Mapped[str] = mapped_column(CITEXT, nullable=False, unique=True)
    password_hash: Mapped[str | None] = mapped_column(Text)
    full_name: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=""
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    is_platform_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        _enum_check("status", _USER_STATUSES, "users_status"),
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
    )


class MfaCredentialRecord(Base, TimestampMixin):
    __tablename__ = "mfa_credentials"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    confirmed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    label: Mapped[str | None] = mapped_column(String(100))

    __table_args__ = (
        _enum_check("kind", _MFA_KINDS, "mfa_credentials_kind"),
        Index("ix_mfa_credentials_user_id_kind", "user_id", "kind"),
    )


class SessionRecord(Base, TimestampMixin):
    __tablename__ = "sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    family_id: Mapped[UUID] = mapped_column(nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_agent: Mapped[str] = mapped_column(
        String(400), nullable=False, default="", server_default=""
    )
    ip_address: Mapped[str | None] = mapped_column(INET)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(80))
    replaced_by_id: Mapped[UUID | None] = mapped_column()

    __table_args__ = (
        Index("ix_sessions_family_id", "family_id"),
        Index("ix_sessions_user_id_expires_at", "user_id", "expires_at"),
        # Partial index over the live set only — the table is mostly rotated rows, and this
        # keeps "sessions I could still use" cheap.
        Index(
            "ix_sessions_active",
            "user_id",
            postgresql_where=text("revoked_at IS NULL AND rotated_at IS NULL"),
        ),
    )


# --- RBAC ---------------------------------------------------------------------------


membership_roles = Table(
    "membership_roles",
    Base.metadata,
    Column("membership_id", ForeignKey("memberships.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class RoleRecord(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(
        String(500), nullable=False, default="", server_default=""
    )
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    # A closed set of short strings, never queried independently of its role — an array is
    # the right shape and avoids a join on the hottest authorization path.
    permissions: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_roles_organization_id_name"),
        Index("ix_roles_organization_id", "organization_id"),
    )


class MembershipRecord(Base, TimestampMixin):
    __tablename__ = "memberships"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    invited_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    joined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    roles: Mapped[list[RoleRecord]] = relationship(
        secondary=membership_roles, lazy="selectin", order_by=RoleRecord.name
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "user_id", name="uq_memberships_organization_id_user_id"
        ),
        _enum_check("status", _MEMBERSHIP_STATUSES, "memberships_status"),
        Index("ix_memberships_user_id", "user_id"),
        Index("ix_memberships_organization_id_status", "organization_id", "status"),
    )


class ApiKeyRecord(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(12), nullable=False, unique=True)
    secret_hash: Mapped[str] = mapped_column(Text, nullable=False)
    permissions: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_api_keys_organization_id", "organization_id"),)


# --- Inventory ----------------------------------------------------------------------


class ApplicationRecord(Base, TimestampMixin):
    __tablename__ = "applications"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)
    language: Mapped[str] = mapped_column(String(10), nullable=False)
    criticality: Mapped[str] = mapped_column(
        String(10), nullable=False, default="MEDIUM", server_default="MEDIUM"
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    repository_url: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(
        String(1000), nullable=False, default="", server_default=""
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_applications_organization_id_slug"),
        _enum_check("language", _LANGUAGES, "applications_language"),
        _enum_check("criticality", _CRITICALITIES, "applications_criticality"),
        Index("ix_applications_organization_id_created_at", "organization_id", "created_at"),
        Index("ix_applications_tags", "tags", postgresql_using="gin"),
    )


class ApplicationEnvironmentRecord(Base, TimestampMixin):
    __tablename__ = "application_environments"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[UUID] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    internet_facing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    protection_mode: Mapped[str] = mapped_column(
        String(10), nullable=False, default="MONITOR", server_default="MONITOR"
    )
    soak_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "application_id", "kind", name="uq_application_environments_application_id_kind"
        ),
        _enum_check("kind", _ENVIRONMENT_KINDS, "application_environments_kind"),
        _enum_check("protection_mode", _PROTECTION_MODES, "application_environments_mode"),
        Index("ix_application_environments_organization_id", "organization_id"),
    )


class AgentRecord(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    application_environment_id: Mapped[UUID] = mapped_column(
        ForeignKey("application_environments.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    hostname: Mapped[str] = mapped_column(
        String(255), nullable=False, default="unknown", server_default="unknown"
    )
    language: Mapped[str] = mapped_column(String(10), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(40), nullable=False)
    runtime_version: Mapped[str] = mapped_column(
        String(80), nullable=False, default="", server_default=""
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="REGISTERED", server_default="REGISTERED"
    )
    config_version: Mapped[str] = mapped_column(
        String(80), nullable=False, default="0", server_default="0"
    )
    cpu_overhead_pct: Mapped[float | None] = mapped_column(Numeric(5, 2))
    memory_mb: Mapped[int | None] = mapped_column(Integer)
    events_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    events_dropped: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    health: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    pinned_version: Mapped[str | None] = mapped_column(String(40))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        _enum_check("status", _AGENT_STATUSES, "agents_status"),
        _enum_check("language", _LANGUAGES, "agents_language"),
        Index("ix_agents_organization_id_status", "organization_id", "status"),
        Index("ix_agents_application_environment_id", "application_environment_id"),
        Index("ix_agents_last_seen_at", "last_seen_at"),
    )


# --- Findings -----------------------------------------------------------------------


class FindingRecord(Base, TimestampMixin):
    """One defect in one application.

    ``identity_hash`` is computed by the worker (ADR-0009) and is the real key. The unique
    constraint on ``(organization_id, identity_hash)`` is what makes ingest idempotent: a
    replayed event stream converges on the same rows instead of multiplying them.
    """

    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[UUID] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_key: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    sink_signature: Mapped[str] = mapped_column(String(400), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    stack_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="OPEN", server_default="OPEN"
    )
    risk_score: Mapped[float] = mapped_column(
        Numeric(4, 2), nullable=False, default=0, server_default=text("0")
    )
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    suppressed_occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    #: Exploitation attempts that blocking mode would have stopped. Kept apart from
    #: occurrence_count because they answer different questions: how often is this flaw
    #: reached, versus how often is it actually being attacked.
    would_block_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    environments_seen: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    route_templates: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    regressed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triage_note: Mapped[str] = mapped_column(
        String(2000), nullable=False, default="", server_default=""
    )
    triaged_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    cwe_id: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "identity_hash", name="uq_findings_organization_id_identity_hash"
        ),
        _enum_check("status", _FINDING_STATUSES, "findings_status"),
        _enum_check("severity", _SEVERITIES, "findings_severity"),
        _enum_check("confidence", _CONFIDENCES, "findings_confidence"),
        # The queue: a tenant's findings by status, worst first. Every list view sorts this
        # way, so the index carries the order rather than the database re-sorting per request.
        Index(
            "ix_findings_organization_id_status_risk_score",
            "organization_id",
            "status",
            text("risk_score DESC"),
        ),
        Index("ix_findings_organization_id_application_id", "organization_id", "application_id"),
        Index("ix_findings_organization_id_last_seen_at", "organization_id", "last_seen_at"),
        # Partial: the sweeper returning expired acceptances to the queue scans only these.
        Index(
            "ix_findings_accepted_until",
            "accepted_until",
            postgresql_where=text("status = 'ACCEPTED_RISK'"),
        ),
    )


class OccurrenceRecord(Base):
    """One sighting of a finding, with its evidence.

    Written sparsely and never updated. The worker rate-limits samples, so this holds a
    handful of representative traces per finding rather than a transcript of production
    traffic — a finding hit a million times does not need a million near-identical copies.
    """

    __tablename__ = "finding_occurrences"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    environment: Mapped[str] = mapped_column(
        String(20), nullable=False, default="", server_default=""
    )
    trace_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", server_default="")
    request_method: Mapped[str] = mapped_column(
        String(10), nullable=False, default="", server_default=""
    )
    request_path: Mapped[str] = mapped_column(
        String(500), nullable=False, default="", server_default=""
    )
    route_template: Mapped[str] = mapped_column(
        String(500), nullable=False, default="", server_default=""
    )
    sink_argument: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    tainted_ranges: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    stack_frames: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    remote_address: Mapped[str | None] = mapped_column(INET)
    attack_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index(
            "ix_finding_occurrences_finding_id_observed_at",
            "finding_id",
            text("observed_at DESC"),
        ),
        Index("ix_finding_occurrences_organization_id", "organization_id"),
    )


class FindingCommentRecord(Base):
    """Triage discussion. Append-only, like the audit log it sits beside.

    Comments are the evidence of how a decision was reached. Allowing them to be edited or
    deleted would let the record of a dismissal be rewritten after an incident.
    """

    __tablename__ = "finding_comments"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    author_label: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=""
    )
    body: Mapped[str] = mapped_column(String(4000), nullable=False)
    status_from: Mapped[str | None] = mapped_column(String(20))
    status_to: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_finding_comments_finding_id_created_at", "finding_id", "created_at"),
        Index("ix_finding_comments_organization_id", "organization_id"),
    )


# --- Audit --------------------------------------------------------------------------


class AuditEventRecord(Base):
    """Append-only. The application database role is granted INSERT and SELECT only."""

    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="SYSTEM", server_default="SYSTEM"
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=""
    )
    resource_type: Mapped[str] = mapped_column(
        String(60), nullable=False, default="", server_default=""
    )
    resource_id: Mapped[str] = mapped_column(
        String(80), nullable=False, default="", server_default=""
    )
    outcome: Mapped[str] = mapped_column(
        String(10), nullable=False, default="SUCCESS", server_default="SUCCESS"
    )
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str] = mapped_column(
        String(400), nullable=False, default="", server_default=""
    )
    request_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=""
    )
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "sequence", name="uq_audit_events_organization_id_sequence"
        ),
        _enum_check("outcome", _AUDIT_OUTCOMES, "audit_events_outcome"),
        _enum_check("actor_type", _ACTOR_TYPES, "audit_events_actor_type"),
        Index("ix_audit_events_organization_id_occurred_at", "organization_id", "occurred_at"),
        Index("ix_audit_events_actor_user_id_occurred_at", "actor_user_id", "occurred_at"),
        Index("ix_audit_events_organization_id_action", "organization_id", "action"),
    )


#: Tables carrying a tenant discriminator that are protected by row-level security. The
#: migration enables and forces RLS on each, and a test asserts this list matches the
#: schema (ADR-0003).
#:
#: ``sessions`` is deliberately excluded. A refresh token is looked up *before* any tenant
#: is known — that lookup is how the tenant is discovered — so an RLS predicate on the
#: session table would make token rotation impossible. Sessions are keyed by a 256-bit
#: token hash and are never enumerated, so the discriminator there is for reporting rather
#: than isolation.
TENANT_TABLES: tuple[str, ...] = (
    "licenses",
    "roles",
    "memberships",
    "api_keys",
    "applications",
    "application_environments",
    "agents",
    "audit_events",
    "findings",
    "finding_occurrences",
    "finding_comments",
)

#: Tables the application may INSERT into and read, but never rewrite.
#:
#: Evidence of something that happened cannot retrospectively have happened differently, and
#: the written reason for dismissing a live vulnerability is exactly what an investigation
#: reads after an incident — and exactly what someone would then most want to change.
APPEND_ONLY_TABLES: tuple[str, ...] = (
    "audit_events",
    "finding_occurrences",
    "finding_comments",
)


class TenantRuleSettingsRecord(Base, TimestampMixin):
    """Which rules one organization has switched off.

    One row per tenant rather than one per disabled rule: the whole set is read on every
    detection decision, and a single row keeps that a point lookup.
    """

    __tablename__ = "tenant_rule_settings"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    #: rule key -> the reason somebody gave for turning it off.
    disabled: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
