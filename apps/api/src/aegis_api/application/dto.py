"""Data transfer objects returned by use cases.

Plain dataclasses, not Pydantic models: the application layer must not depend on the
serialization library the HTTP layer happens to use. The interface layer maps these onto
response schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Page(Generic[T]):
    """A cursor-paginated slice (see docs/04-api-specification.md §1.2)."""

    items: list[T]
    next_cursor: str | None
    limit: int

    @property
    def has_more(self) -> bool:
        return self.next_cursor is not None


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime
    session_id: UUID
    token_type: str = "Bearer"  # noqa: S105 - a scheme name, not a credential


@dataclass(frozen=True, slots=True)
class MfaChallenge:
    """Issued when credentials are correct but a second factor is still required."""

    challenge_token: str
    expires_at: datetime
    methods: list[str]


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    """Either a token pair or an MFA challenge — never both."""

    tokens: TokenPair | None = None
    challenge: MfaChallenge | None = None

    @property
    def mfa_required(self) -> bool:
        return self.challenge is not None


@dataclass(frozen=True, slots=True)
class OrganizationSummary:
    id: UUID
    name: str
    slug: str
    status: str


@dataclass(frozen=True, slots=True)
class RoleSummary:
    id: UUID
    name: str
    description: str
    is_system: bool
    permissions: list[str]


@dataclass(frozen=True, slots=True)
class MemberSummary:
    membership_id: UUID
    user_id: UUID
    email: str
    full_name: str
    status: str
    roles: list[RoleSummary]
    permissions: list[str]
    joined_at: datetime | None
    last_login_at: datetime | None


@dataclass(frozen=True, slots=True)
class CurrentPrincipal:
    """The payload behind ``GET /auth/me``."""

    user_id: UUID
    email: str
    full_name: str
    mfa_enabled: bool
    is_platform_admin: bool
    organization: OrganizationSummary
    roles: list[RoleSummary]
    permissions: list[str]
    session_id: UUID | None


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    organization: OrganizationSummary
    user_id: UUID
    email: str
    tokens: TokenPair


@dataclass(frozen=True, slots=True)
class MfaEnrolmentResult:
    """Returned exactly once, at enrolment. Recovery codes are never retrievable again."""

    secret: str
    provisioning_uri: str
    recovery_codes: list[str]


@dataclass(frozen=True, slots=True)
class ApiKeySummary:
    id: UUID
    name: str
    prefix: str
    permissions: list[str]
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


@dataclass(frozen=True, slots=True)
class ApiKeyIssued:
    """The plaintext secret appears here and nowhere else, ever."""

    summary: ApiKeySummary
    plaintext_key: str


@dataclass(frozen=True, slots=True)
class EnvironmentSummary:
    id: UUID
    application_id: UUID
    kind: str
    internet_facing: bool
    protection_mode: str
    created_at: datetime | None


@dataclass(frozen=True, slots=True)
class ApplicationSummary:
    id: UUID
    name: str
    slug: str
    language: str
    criticality: str
    tags: list[str]
    repository_url: str | None
    description: str
    created_at: datetime | None
    environments: list[EnvironmentSummary] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AgentSummary:
    id: UUID
    application_environment_id: UUID
    fingerprint: str
    hostname: str
    language: str
    agent_version: str
    runtime_version: str
    status: str
    config_version: str
    cpu_overhead_pct: float | None
    memory_mb: int | None
    events_sent: int
    events_dropped: int
    pinned_version: str | None
    last_seen_at: datetime | None
    created_at: datetime | None


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    """What an agent receives after registering."""

    agent: AgentSummary
    agent_token: str
    agent_token_expires_at: datetime
    config_version: str
    heartbeat_interval_seconds: int


@dataclass(frozen=True, slots=True)
class AgentConfiguration:
    """The signed-bundle descriptor an agent polls for."""

    config_version: str
    protection_mode: str
    capture_request_body: str
    max_value_length: int
    redact_keys: list[str]
    cpu_budget_pct: float
    enabled_rules: list[str]
    heartbeat_interval_seconds: int


@dataclass(frozen=True, slots=True)
class AuditEventSummary:
    id: UUID
    sequence: int
    action: str
    actor_type: str
    actor_user_id: UUID | None
    actor_label: str
    resource_type: str
    resource_id: str
    outcome: str
    ip_address: str | None
    request_id: str
    metadata: dict[str, object]
    occurred_at: datetime | None


@dataclass(frozen=True, slots=True)
class ChainVerification:
    intact: bool
    entries_checked: int
    first_broken_sequence: int | None
