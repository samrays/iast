"""Request and response schemas.

Pydantic models used purely for transport validation and serialization. They mirror the
application DTOs rather than sharing them, so a change to the wire format never forces a
change to a use case's return type.
"""

from __future__ import annotations

from dataclasses import fields as dataclass_fields
from datetime import datetime
from typing import Annotated, Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from ...application import dto
from ...domain.entities import Criticality, EnvironmentKind, Language, ProtectionMode

T = TypeVar("T")


def _shallow(item: object) -> dict[str, Any]:
    """Flatten a slotted dataclass into kwargs.

    ``__dict__`` does not exist on ``slots=True`` dataclasses, and ``asdict`` recurses into
    nested dataclasses — neither is what a one-level schema constructor wants.
    """
    return {f.name: getattr(item, f.name) for f in dataclass_fields(item)}  # type: ignore[arg-type]


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)


class PageMeta(Schema):
    next_cursor: str | None = None
    has_more: bool = False
    limit: int


class PageResponse(BaseModel, Generic[T]):
    items: list[T]
    page: PageMeta

    @classmethod
    def of(cls, page: dto.Page[Any], items: list[T]) -> PageResponse[T]:
        """Attach cursor metadata to an already-mapped list of response models.

        ``Page[Any]`` rather than ``Page[object]``: only the pagination fields are read,
        and ``Page`` is invariant in its element type, so ``Page[object]`` would reject
        every concrete page the use cases actually return.
        """
        return cls(
            items=items,
            page=PageMeta(next_cursor=page.next_cursor, has_more=page.has_more, limit=page.limit),
        )


# --- Auth ------------------------------------------------------------------------------

Password = Annotated[str, Field(min_length=8, max_length=256)]


class RegisterRequest(Schema):
    organization_name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    password: Password
    full_name: str = Field(default="", max_length=200)


class LoginRequest(Schema):
    email: EmailStr
    password: Password
    organization_slug: str | None = Field(default=None, max_length=63)


class MfaVerifyRequest(Schema):
    challenge_token: str = Field(min_length=1)
    code: str = Field(min_length=4, max_length=20)


class RefreshRequest(Schema):
    #: Optional: browsers send the token in an HttpOnly cookie instead.
    refresh_token: str | None = None


class ChangePasswordRequest(Schema):
    current_password: Password
    new_password: Password


class MfaEnrolRequest(Schema):
    password: Password


class MfaConfirmRequest(Schema):
    code: str = Field(min_length=4, max_length=10)


class MfaDisableRequest(Schema):
    password: Password


class TokenResponse(Schema):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - a scheme name
    expires_at: datetime
    #: Omitted when the refresh token was delivered as a cookie.
    refresh_token: str | None = None
    refresh_expires_at: datetime | None = None
    session_id: UUID

    @classmethod
    def of(cls, tokens: dto.TokenPair, *, include_refresh: bool) -> TokenResponse:
        return cls(
            access_token=tokens.access_token,
            expires_at=tokens.access_token_expires_at,
            refresh_token=tokens.refresh_token if include_refresh else None,
            refresh_expires_at=tokens.refresh_token_expires_at if include_refresh else None,
            session_id=tokens.session_id,
        )


class MfaChallengeResponse(Schema):
    mfa_required: bool = True
    challenge_token: str
    expires_at: datetime
    methods: list[str]


class OrganizationResponse(Schema):
    id: UUID
    name: str
    slug: str
    status: str

    @classmethod
    def of(cls, item: dto.OrganizationSummary) -> OrganizationResponse:
        return cls(id=item.id, name=item.name, slug=item.slug, status=item.status)


class RoleResponse(Schema):
    id: UUID
    name: str
    description: str
    is_system: bool
    permissions: list[str]

    @classmethod
    def of(cls, item: dto.RoleSummary) -> RoleResponse:
        return cls(
            id=item.id,
            name=item.name,
            description=item.description,
            is_system=item.is_system,
            permissions=item.permissions,
        )


class RegistrationResponse(Schema):
    organization: OrganizationResponse
    user_id: UUID
    email: str
    tokens: TokenResponse


class CurrentPrincipalResponse(Schema):
    user_id: UUID
    email: str
    full_name: str
    mfa_enabled: bool
    is_platform_admin: bool
    organization: OrganizationResponse
    roles: list[RoleResponse]
    permissions: list[str]
    session_id: UUID | None

    @classmethod
    def of(cls, item: dto.CurrentPrincipal) -> CurrentPrincipalResponse:
        return cls(
            user_id=item.user_id,
            email=item.email,
            full_name=item.full_name,
            mfa_enabled=item.mfa_enabled,
            is_platform_admin=item.is_platform_admin,
            organization=OrganizationResponse.of(item.organization),
            roles=[RoleResponse.of(r) for r in item.roles],
            permissions=item.permissions,
            session_id=item.session_id,
        )


class MfaEnrolResponse(Schema):
    secret: str
    provisioning_uri: str
    recovery_codes: list[str]


class LogoutResponse(Schema):
    sessions_revoked: int


# --- Organization and members -------------------------------------------------------------


class UpdateOrganizationRequest(Schema):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    settings: dict[str, object] | None = None


class InviteMemberRequest(Schema):
    email: EmailStr
    full_name: str = Field(default="", max_length=200)
    role_ids: list[UUID] = Field(min_length=1)


class UpdateMemberRequest(Schema):
    role_ids: list[UUID] = Field(min_length=1)


class MemberResponse(Schema):
    membership_id: UUID
    user_id: UUID
    email: str
    full_name: str
    status: str
    roles: list[RoleResponse]
    permissions: list[str]
    joined_at: datetime | None
    last_login_at: datetime | None

    @classmethod
    def of(cls, item: dto.MemberSummary) -> MemberResponse:
        return cls(
            membership_id=item.membership_id,
            user_id=item.user_id,
            email=item.email,
            full_name=item.full_name,
            status=item.status,
            roles=[RoleResponse.of(r) for r in item.roles],
            permissions=item.permissions,
            joined_at=item.joined_at,
            last_login_at=item.last_login_at,
        )


class CreateRoleRequest(Schema):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(min_length=1)


class UpdateRoleRequest(Schema):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = None


class PermissionCatalogueEntry(Schema):
    value: str
    resource: str
    action: str
    privileged: bool


# --- AI Analysis --------------------------------------------------------------------


class AnalyzeFindingRequest(Schema):
    kind: Literal["ROOT_CAUSE", "REMEDIATION", "TRIAGE_ASSESSMENT"] = "ROOT_CAUSE"


class ReviewAnalysisRequest(Schema):
    accept: bool
    note: str = ""


class AiAnalysisResponse(Schema):
    id: UUID
    organization_id: UUID
    finding_id: UUID
    kind: str
    summary: str
    content: str
    status: str
    model: str
    prompt_hash: str
    input_tokens: int
    output_tokens: int
    reviewed_by: UUID | None = None
    review_note: str = ""
    failure_reason: str = ""
    created_at: datetime | None = None
    reviewed_at: datetime | None = None

    @classmethod
    def of(cls, entity: Any) -> AiAnalysisResponse:
        return cls(
            id=entity.id,
            organization_id=entity.organization_id,
            finding_id=entity.finding_id,
            kind=entity.kind.value if hasattr(entity.kind, "value") else str(entity.kind),
            summary=entity.summary,
            content=entity.content,
            status=entity.status.value if hasattr(entity.status, "value") else str(entity.status),
            model=entity.model,
            prompt_hash=entity.prompt_hash,
            input_tokens=entity.input_tokens,
            output_tokens=entity.output_tokens,
            reviewed_by=entity.reviewed_by,
            review_note=entity.review_note,
            failure_reason=entity.failure_reason,
            created_at=entity.created_at,
            reviewed_at=entity.reviewed_at,
        )


# --- API keys --------------------------------------------------------------------------------


class CreateApiKeyRequest(Schema):
    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(min_length=1)
    expires_in_days: int | None = Field(default=90, ge=1, le=730)


class ApiKeyResponse(Schema):
    id: UUID
    name: str
    prefix: str
    permissions: list[str]
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    is_active: bool

    @classmethod
    def of(cls, item: dto.ApiKeySummary) -> ApiKeyResponse:
        return cls(
            id=item.id,
            name=item.name,
            prefix=item.prefix,
            permissions=item.permissions,
            created_at=item.created_at,
            expires_at=item.expires_at,
            last_used_at=item.last_used_at,
            revoked_at=item.revoked_at,
            is_active=item.is_active,
        )


class ApiKeyIssuedResponse(Schema):
    api_key: ApiKeyResponse
    #: Shown once. It cannot be retrieved again — only the hash is stored.
    secret: str


# --- Inventory --------------------------------------------------------------------------------


class EnvironmentSpec(Schema):
    kind: EnvironmentKind
    internet_facing: bool = False


class CreateApplicationRequest(Schema):
    name: str = Field(min_length=1, max_length=120)
    language: Language
    criticality: Criticality = Criticality.MEDIUM
    tags: list[str] = Field(default_factory=list, max_length=20)
    repository_url: str | None = Field(default=None, max_length=500)
    description: str = Field(default="", max_length=1000)
    environments: list[EnvironmentSpec] = Field(default_factory=list)


class UpdateApplicationRequest(Schema):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    criticality: Criticality | None = None
    tags: list[str] | None = Field(default=None, max_length=20)
    repository_url: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=1000)


class CreateEnvironmentRequest(Schema):
    kind: EnvironmentKind
    internet_facing: bool = False


class SetProtectionModeRequest(Schema):
    mode: ProtectionMode


class EnvironmentResponse(Schema):
    id: UUID
    application_id: UUID
    kind: str
    internet_facing: bool
    protection_mode: str
    created_at: datetime | None

    @classmethod
    def of(cls, item: dto.EnvironmentSummary) -> EnvironmentResponse:
        return cls(
            id=item.id,
            application_id=item.application_id,
            kind=item.kind,
            internet_facing=item.internet_facing,
            protection_mode=item.protection_mode,
            created_at=item.created_at,
        )


class ApplicationResponse(Schema):
    id: UUID
    name: str
    slug: str
    language: str
    criticality: str
    tags: list[str]
    repository_url: str | None
    description: str
    created_at: datetime | None
    environments: list[EnvironmentResponse]

    @classmethod
    def of(cls, item: dto.ApplicationSummary) -> ApplicationResponse:
        return cls(
            id=item.id,
            name=item.name,
            slug=item.slug,
            language=item.language,
            criticality=item.criticality,
            tags=item.tags,
            repository_url=item.repository_url,
            description=item.description,
            created_at=item.created_at,
            environments=[EnvironmentResponse.of(e) for e in item.environments],
        )


# --- Agents ------------------------------------------------------------------------------------


class AgentRegisterRequest(Schema):
    application_name: str = Field(min_length=1, max_length=120)
    environment: EnvironmentKind
    language: Language
    fingerprint: str = Field(min_length=8, max_length=128)
    hostname: str = Field(default="unknown", max_length=255)
    agent_version: str = Field(min_length=1, max_length=40)
    runtime_version: str = Field(default="", max_length=80)


class AgentHeartbeatRequest(Schema):
    cpu_overhead_pct: float | None = Field(default=None, ge=0, le=100)
    memory_mb: int | None = Field(default=None, ge=0)
    events_sent: int = Field(default=0, ge=0)
    events_dropped: int = Field(default=0, ge=0)
    health: dict[str, object] | None = None


class UpdateAgentRequest(Schema):
    enabled: bool | None = None
    pinned_version: str | None = Field(default=None, max_length=40)


class AgentResponse(Schema):
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

    @classmethod
    def of(cls, item: dto.AgentSummary) -> AgentResponse:
        return cls(**_shallow(item))


class AgentRegistrationResponse(Schema):
    agent: AgentResponse
    agent_token: str
    agent_token_expires_at: datetime
    config_version: str
    heartbeat_interval_seconds: int


class AgentConfigurationResponse(Schema):
    config_version: str
    protection_mode: str
    capture_request_body: str
    max_value_length: int
    redact_keys: list[str]
    cpu_budget_pct: float
    enabled_rules: list[str]
    heartbeat_interval_seconds: int

    @classmethod
    def of(cls, item: dto.AgentConfiguration) -> AgentConfigurationResponse:
        return cls(**_shallow(item))


# --- Audit --------------------------------------------------------------------------------------


class AuditEventResponse(Schema):
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

    @classmethod
    def of(cls, item: dto.AuditEventSummary) -> AuditEventResponse:
        return cls(**_shallow(item))


class ChainVerificationResponse(Schema):
    intact: bool
    entries_checked: int
    first_broken_sequence: int | None


# --- Operations -----------------------------------------------------------------------------------


class HealthResponse(Schema):
    status: str
    service: str
    version: str
    environment: str


class ReadinessResponse(Schema):
    status: str
    checks: dict[str, str]


# --- Findings -----------------------------------------------------------------------


class RiskFactorResponse(Schema):
    name: str
    delta: float
    reason: str


class FindingResponse(Schema):
    id: UUID
    application_id: UUID
    rule_key: str
    title: str
    severity: str
    confidence: str
    status: str
    risk_score: float
    risk_factors: list[RiskFactorResponse]
    occurrence_count: int
    suppressed_occurrence_count: int
    would_block_count: int
    environments_seen: list[str]
    route_templates: list[str]
    sink_signature: str
    source_kind: str
    cwe_id: int | None
    regressed: bool
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    accepted_until: datetime | None
    triage_note: str

    @classmethod
    def of(cls, finding: Any) -> FindingResponse:
        return cls(
            id=finding.id,
            application_id=finding.application_id,
            rule_key=finding.rule_key,
            title=finding.title,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            status=finding.status.value,
            risk_score=finding.risk_score,
            risk_factors=[
                RiskFactorResponse(name=name, delta=delta, reason=reason)
                for name, delta, reason in finding.risk_factors
            ],
            occurrence_count=finding.occurrence_count,
            suppressed_occurrence_count=finding.suppressed_occurrence_count,
            would_block_count=finding.would_block_count,
            environments_seen=list(finding.environments_seen),
            route_templates=list(finding.route_templates),
            sink_signature=finding.sink_signature,
            source_kind=finding.source_kind,
            cwe_id=finding.cwe_id,
            regressed=finding.regressed,
            first_seen_at=finding.first_seen_at,
            last_seen_at=finding.last_seen_at,
            accepted_until=finding.accepted_until,
            triage_note=finding.triage_note,
        )


class TaintRangeResponse(Schema):
    start: int
    length: int
    source: str
    source_name: str


class StackFrameResponse(Schema):
    declaring_class: str
    method_name: str
    line_number: int
    application_code: bool


class OccurrenceResponse(Schema):
    id: UUID
    environment: str
    trace_id: str
    request_method: str
    request_path: str
    route_template: str
    sink_argument: str
    tainted_ranges: list[TaintRangeResponse]
    stack_frames: list[StackFrameResponse]
    remote_address: str
    attack_detected: bool
    observed_at: datetime | None

    @classmethod
    def of(cls, occurrence: Any) -> OccurrenceResponse:
        return cls(
            id=occurrence.id,
            environment=occurrence.environment,
            trace_id=occurrence.trace_id,
            request_method=occurrence.request_method,
            request_path=occurrence.request_path,
            route_template=occurrence.route_template,
            sink_argument=occurrence.sink_argument,
            tainted_ranges=[
                TaintRangeResponse(start=s, length=length, source=source, source_name=name)
                for s, length, source, name in occurrence.tainted_ranges
            ],
            stack_frames=[
                StackFrameResponse(
                    declaring_class=declaring_class,
                    method_name=method,
                    line_number=line,
                    application_code=is_app,
                )
                for declaring_class, method, line, is_app in occurrence.stack_frames
            ],
            remote_address=occurrence.remote_address,
            attack_detected=occurrence.attack_detected,
            observed_at=occurrence.observed_at,
        )


class FindingCommentResponse(Schema):
    id: UUID
    author_id: UUID | None
    author_label: str
    body: str
    status_from: str | None
    status_to: str | None
    created_at: datetime | None


class FindingDetailResponse(FindingResponse):
    occurrences: list[OccurrenceResponse]
    comments: list[FindingCommentResponse]

    @classmethod
    def of(cls, finding: Any, occurrences: Any = (), comments: Any = ()) -> FindingDetailResponse:
        base = FindingResponse.of(finding)
        return cls(
            **base.model_dump(),
            occurrences=[OccurrenceResponse.of(o) for o in occurrences],
            comments=[FindingCommentResponse(**c) for c in comments],
        )


class TriageRequest(Schema):
    status: Literal["OPEN", "CONFIRMED", "REMEDIATED", "FALSE_POSITIVE", "ACCEPTED_RISK"]
    note: str = Field(default="", max_length=2000)
    #: Only meaningful for ACCEPTED_RISK. Bounded so nobody can accept a risk for a century
    #: and call it expiry.
    accepted_for_days: int | None = Field(default=None, ge=1, le=365)


class FindingCommentRequest(Schema):
    body: str = Field(min_length=1, max_length=4000)


class RuleResponse(Schema):
    key: str
    title: str
    severity: str
    cwe_id: int | None
    description: str
    remediation: str
    enabled: bool
    disabled_reason: str

    @classmethod
    def of(cls, view: Any) -> RuleResponse:
        return cls(
            key=view.rule.key,
            title=view.rule.title,
            severity=view.rule.severity.value,
            cwe_id=view.rule.cwe_id,
            description=view.rule.description,
            remediation=view.rule.remediation,
            enabled=view.enabled,
            disabled_reason=view.disabled_reason,
        )


class RuleToggleRequest(Schema):
    enabled: bool
    #: Required when switching a rule off; the domain rejects a blank one.
    reason: str = Field(default="", max_length=500)


class BulkTriageRequest(Schema):
    finding_ids: list[UUID] = Field(min_length=1, max_length=200)
    status: Literal["OPEN", "CONFIRMED", "REMEDIATED", "FALSE_POSITIVE", "ACCEPTED_RISK"]
    note: str = Field(default="", max_length=2000)
    accepted_for_days: int | None = Field(default=None, ge=1, le=365)


class BulkTriageOutcomeResponse(Schema):
    finding_id: UUID
    applied: bool
    error: str


class BulkTriageResponse(Schema):
    applied: int
    rejected: int
    outcomes: list[BulkTriageOutcomeResponse]

    @classmethod
    def of(cls, outcomes: Any) -> BulkTriageResponse:
        items = [
            BulkTriageOutcomeResponse(finding_id=o.finding_id, applied=o.applied, error=o.error)
            for o in outcomes
        ]
        return cls(
            applied=sum(1 for o in items if o.applied),
            rejected=sum(1 for o in items if not o.applied),
            outcomes=items,
        )
