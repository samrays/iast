"""Translation between persistence records and domain entities.

Kept in one module so the mapping for an entity is always in a predictable place, and so
that adding a field is a single-file change on the persistence side.
"""

from __future__ import annotations

from ...domain.entities import (
    ActorType,
    Agent,
    AgentStatus,
    ApiKey,
    Application,
    ApplicationEnvironment,
    AuditEvent,
    AuditOutcome,
    Confidence,
    Criticality,
    EnvironmentKind,
    Finding,
    FindingStatus,
    Language,
    License,
    LicenseTier,
    Membership,
    MembershipStatus,
    MfaCredential,
    MfaKind,
    Occurrence,
    Organization,
    OrganizationStatus,
    ProtectionMode,
    Role,
    Session,
    Severity,
    User,
    UserStatus,
)
from ...domain.entities.ai import AiAnalysis, AnalysisKind, AnalysisStatus
from ...domain.entities.rules import TenantRuleSettings
from ...domain.permissions import Permission
from ...domain.value_objects import ApiKeyPrefix, EmailAddress, PasswordHash, Slug, TokenHash
from .models import (
    AgentRecord,
    AiAnalysisRecord,
    ApiKeyRecord,
    ApplicationEnvironmentRecord,
    ApplicationRecord,
    AuditEventRecord,
    FindingRecord,
    LicenseRecord,
    MembershipRecord,
    MfaCredentialRecord,
    OccurrenceRecord,
    OrganizationRecord,
    RoleRecord,
    SessionRecord,
    TenantRuleSettingsRecord,
    UserRecord,
)


def _ip(value: object) -> str | None:
    """Normalize an INET column to a string.

    asyncpg returns ``ipaddress.IPv4Address``/``IPv6Address`` objects for INET columns; the
    domain models the address as an opaque string because it is recorded for forensics, not
    compared or routed on.
    """
    return None if value is None else str(value)


def _permissions(raw: list[str]) -> frozenset[Permission]:
    """Parse stored permissions, discarding values no longer in the catalogue.

    Discarding is safe here and only here: a permission removed from the product must not
    prevent an existing role from loading, and dropping it fails *closed*.
    """
    parsed: set[Permission] = set()
    for item in raw:
        try:
            parsed.add(Permission(item))
        except ValueError:
            continue
    return frozenset(parsed)


# --- Organization ---------------------------------------------------------------------


def organization_to_domain(record: OrganizationRecord) -> Organization:
    return Organization(
        id=record.id,
        name=record.name,
        slug=Slug(record.slug),
        status=OrganizationStatus(record.status),
        settings=dict(record.settings or {}),
        created_at=record.created_at,
        updated_at=record.updated_at,
        deletion_scheduled_at=record.deletion_scheduled_at,
    )


def organization_to_record(entity: Organization) -> OrganizationRecord:
    return OrganizationRecord(
        id=entity.id,
        name=entity.name,
        slug=entity.slug.value,
        status=entity.status.value,
        settings=entity.settings,
        deletion_scheduled_at=entity.deletion_scheduled_at,
    )


def apply_organization(record: OrganizationRecord, entity: Organization) -> None:
    record.name = entity.name
    record.status = entity.status.value
    record.settings = dict(entity.settings)
    record.deletion_scheduled_at = entity.deletion_scheduled_at


# --- License ---------------------------------------------------------------------------


def license_to_domain(record: LicenseRecord) -> License:
    return License(
        id=record.id,
        organization_id=record.organization_id,
        tier=LicenseTier(record.tier),
        max_applications=record.max_applications,
        max_agents=record.max_agents,
        max_users=record.max_users,
        ai_enabled=record.ai_enabled,
        protection_enabled=record.protection_enabled,
        valid_until=record.valid_until,
    )


def license_to_record(entity: License) -> LicenseRecord:
    return LicenseRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        tier=entity.tier.value,
        max_applications=entity.max_applications,
        max_agents=entity.max_agents,
        max_users=entity.max_users,
        ai_enabled=entity.ai_enabled,
        protection_enabled=entity.protection_enabled,
        valid_until=entity.valid_until,
    )


# --- User --------------------------------------------------------------------------------


def user_to_domain(record: UserRecord) -> User:
    return User(
        id=record.id,
        email=EmailAddress(record.email),
        password_hash=PasswordHash(record.password_hash) if record.password_hash else None,
        full_name=record.full_name,
        status=UserStatus(record.status),
        is_platform_admin=record.is_platform_admin,
        mfa_enabled=record.mfa_enabled,
        failed_login_count=record.failed_login_count,
        locked_until=record.locked_until,
        password_changed_at=record.password_changed_at,
        last_login_at=record.last_login_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def user_to_record(entity: User) -> UserRecord:
    return UserRecord(
        id=entity.id,
        email=entity.email.value,
        password_hash=entity.password_hash.value if entity.password_hash else None,
        full_name=entity.full_name,
        status=entity.status.value,
        is_platform_admin=entity.is_platform_admin,
        mfa_enabled=entity.mfa_enabled,
        failed_login_count=entity.failed_login_count,
        locked_until=entity.locked_until,
        password_changed_at=entity.password_changed_at,
        last_login_at=entity.last_login_at,
    )


def apply_user(record: UserRecord, entity: User) -> None:
    record.email = entity.email.value
    record.password_hash = entity.password_hash.value if entity.password_hash else None
    record.full_name = entity.full_name
    record.status = entity.status.value
    record.is_platform_admin = entity.is_platform_admin
    record.mfa_enabled = entity.mfa_enabled
    record.failed_login_count = entity.failed_login_count
    record.locked_until = entity.locked_until
    record.password_changed_at = entity.password_changed_at
    record.last_login_at = entity.last_login_at


# --- MFA ---------------------------------------------------------------------------------


def mfa_to_domain(record: MfaCredentialRecord) -> MfaCredential:
    return MfaCredential(
        id=record.id,
        user_id=record.user_id,
        kind=MfaKind(record.kind),
        secret_encrypted=record.secret_encrypted,
        confirmed=record.confirmed,
        consumed_at=record.consumed_at,
        last_used_at=record.last_used_at,
        label=record.label,
        created_at=record.created_at,
    )


def mfa_to_record(entity: MfaCredential) -> MfaCredentialRecord:
    return MfaCredentialRecord(
        id=entity.id,
        user_id=entity.user_id,
        kind=entity.kind.value,
        secret_encrypted=entity.secret_encrypted,
        confirmed=entity.confirmed,
        consumed_at=entity.consumed_at,
        last_used_at=entity.last_used_at,
        label=entity.label,
    )


def apply_mfa(record: MfaCredentialRecord, entity: MfaCredential) -> None:
    record.confirmed = entity.confirmed
    record.consumed_at = entity.consumed_at
    record.last_used_at = entity.last_used_at


# --- Role and membership -------------------------------------------------------------------


def role_to_domain(record: RoleRecord) -> Role:
    return Role(
        id=record.id,
        organization_id=record.organization_id,
        name=record.name,
        description=record.description,
        is_system=record.is_system,
        permissions=_permissions(list(record.permissions or [])),
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def role_to_record(entity: Role) -> RoleRecord:
    return RoleRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        name=entity.name,
        description=entity.description,
        is_system=entity.is_system,
        permissions=sorted(p.value for p in entity.permissions),
    )


def apply_role(record: RoleRecord, entity: Role) -> None:
    record.name = entity.name
    record.description = entity.description
    record.permissions = sorted(p.value for p in entity.permissions)


def membership_to_domain(record: MembershipRecord) -> Membership:
    return Membership(
        id=record.id,
        organization_id=record.organization_id,
        user_id=record.user_id,
        roles=tuple(role_to_domain(r) for r in record.roles),
        status=MembershipStatus(record.status),
        invited_by=record.invited_by,
        joined_at=record.joined_at,
        created_at=record.created_at,
    )


def membership_to_record(entity: Membership) -> MembershipRecord:
    return MembershipRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        user_id=entity.user_id,
        status=entity.status.value,
        invited_by=entity.invited_by,
        joined_at=entity.joined_at,
    )


# --- Session -------------------------------------------------------------------------------


def session_to_domain(record: SessionRecord) -> Session:
    return Session(
        id=record.id,
        user_id=record.user_id,
        organization_id=record.organization_id,
        family_id=record.family_id,
        refresh_token_hash=TokenHash(record.refresh_token_hash),
        expires_at=record.expires_at,
        user_agent=record.user_agent,
        ip_address=_ip(record.ip_address),
        rotated_at=record.rotated_at,
        revoked_at=record.revoked_at,
        revoked_reason=record.revoked_reason,
        replaced_by_id=record.replaced_by_id,
        created_at=record.created_at,
    )


def session_to_record(entity: Session) -> SessionRecord:
    return SessionRecord(
        id=entity.id,
        user_id=entity.user_id,
        organization_id=entity.organization_id,
        family_id=entity.family_id,
        refresh_token_hash=entity.refresh_token_hash.value,
        user_agent=entity.user_agent,
        ip_address=entity.ip_address,
        expires_at=entity.expires_at,
        rotated_at=entity.rotated_at,
        revoked_at=entity.revoked_at,
        revoked_reason=entity.revoked_reason,
        replaced_by_id=entity.replaced_by_id,
    )


def apply_session(record: SessionRecord, entity: Session) -> None:
    record.rotated_at = entity.rotated_at
    record.revoked_at = entity.revoked_at
    record.revoked_reason = entity.revoked_reason
    record.replaced_by_id = entity.replaced_by_id


# --- API key -------------------------------------------------------------------------------


def api_key_to_domain(record: ApiKeyRecord) -> ApiKey:
    return ApiKey(
        id=record.id,
        organization_id=record.organization_id,
        name=record.name,
        prefix=ApiKeyPrefix(record.prefix),
        secret_hash=record.secret_hash,
        permissions=_permissions(list(record.permissions or [])),
        created_by=record.created_by,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        last_used_at=record.last_used_at,
        created_at=record.created_at,
    )


def api_key_to_record(entity: ApiKey) -> ApiKeyRecord:
    return ApiKeyRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        name=entity.name,
        prefix=entity.prefix.value,
        secret_hash=entity.secret_hash,
        permissions=sorted(p.value for p in entity.permissions),
        created_by=entity.created_by,
        expires_at=entity.expires_at,
        revoked_at=entity.revoked_at,
        last_used_at=entity.last_used_at,
    )


def apply_api_key(record: ApiKeyRecord, entity: ApiKey) -> None:
    record.name = entity.name
    record.permissions = sorted(p.value for p in entity.permissions)
    record.expires_at = entity.expires_at
    record.revoked_at = entity.revoked_at
    record.last_used_at = entity.last_used_at


# --- Inventory -------------------------------------------------------------------------------


def application_to_domain(record: ApplicationRecord) -> Application:
    return Application(
        id=record.id,
        organization_id=record.organization_id,
        name=record.name,
        slug=Slug(record.slug),
        language=Language(record.language),
        criticality=Criticality(record.criticality),
        tags=tuple(record.tags or []),
        repository_url=record.repository_url,
        description=record.description,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def application_to_record(entity: Application) -> ApplicationRecord:
    return ApplicationRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        name=entity.name,
        slug=entity.slug.value,
        language=entity.language.value,
        criticality=entity.criticality.value,
        tags=list(entity.tags),
        repository_url=entity.repository_url,
        description=entity.description,
    )


def apply_application(record: ApplicationRecord, entity: Application) -> None:
    record.name = entity.name
    record.criticality = entity.criticality.value
    record.tags = list(entity.tags)
    record.repository_url = entity.repository_url
    record.description = entity.description


def environment_to_domain(record: ApplicationEnvironmentRecord) -> ApplicationEnvironment:
    return ApplicationEnvironment(
        id=record.id,
        organization_id=record.organization_id,
        application_id=record.application_id,
        kind=EnvironmentKind(record.kind),
        internet_facing=record.internet_facing,
        protection_mode=ProtectionMode(record.protection_mode),
        soak_completed_at=record.soak_completed_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def environment_to_record(entity: ApplicationEnvironment) -> ApplicationEnvironmentRecord:
    return ApplicationEnvironmentRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        application_id=entity.application_id,
        kind=entity.kind.value,
        internet_facing=entity.internet_facing,
        protection_mode=entity.protection_mode.value,
        soak_completed_at=entity.soak_completed_at,
    )


def apply_environment(record: ApplicationEnvironmentRecord, entity: ApplicationEnvironment) -> None:
    record.internet_facing = entity.internet_facing
    record.protection_mode = entity.protection_mode.value
    record.soak_completed_at = entity.soak_completed_at


def agent_to_domain(record: AgentRecord) -> Agent:
    return Agent(
        id=record.id,
        organization_id=record.organization_id,
        application_environment_id=record.application_environment_id,
        fingerprint=record.fingerprint,
        hostname=record.hostname,
        language=Language(record.language),
        agent_version=record.agent_version,
        runtime_version=record.runtime_version,
        status=AgentStatus(record.status),
        config_version=record.config_version,
        cpu_overhead_pct=(
            float(record.cpu_overhead_pct) if record.cpu_overhead_pct is not None else None
        ),
        memory_mb=record.memory_mb,
        events_sent=record.events_sent,
        events_dropped=record.events_dropped,
        health=dict(record.health or {}),
        pinned_version=record.pinned_version,
        last_seen_at=record.last_seen_at,
        created_at=record.created_at,
    )


def agent_to_record(entity: Agent) -> AgentRecord:
    return AgentRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        application_environment_id=entity.application_environment_id,
        fingerprint=entity.fingerprint,
        hostname=entity.hostname,
        language=entity.language.value,
        agent_version=entity.agent_version,
        runtime_version=entity.runtime_version,
        status=entity.status.value,
        config_version=entity.config_version,
        cpu_overhead_pct=entity.cpu_overhead_pct,
        memory_mb=entity.memory_mb,
        events_sent=entity.events_sent,
        events_dropped=entity.events_dropped,
        health=entity.health,
        pinned_version=entity.pinned_version,
        last_seen_at=entity.last_seen_at,
    )


def apply_agent(record: AgentRecord, entity: Agent) -> None:
    record.application_environment_id = entity.application_environment_id
    record.hostname = entity.hostname
    record.agent_version = entity.agent_version
    record.runtime_version = entity.runtime_version
    record.status = entity.status.value
    record.config_version = entity.config_version
    record.cpu_overhead_pct = entity.cpu_overhead_pct
    record.memory_mb = entity.memory_mb
    record.events_sent = entity.events_sent
    record.events_dropped = entity.events_dropped
    record.health = dict(entity.health)
    record.pinned_version = entity.pinned_version
    record.last_seen_at = entity.last_seen_at


# --- Audit -----------------------------------------------------------------------------------


def audit_to_domain(record: AuditEventRecord) -> AuditEvent:
    return AuditEvent(
        id=record.id,
        organization_id=record.organization_id,
        sequence=record.sequence,
        action=record.action,
        actor_type=ActorType(record.actor_type),
        actor_user_id=record.actor_user_id,
        actor_label=record.actor_label,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        outcome=AuditOutcome(record.outcome),
        ip_address=_ip(record.ip_address),
        user_agent=record.user_agent,
        request_id=record.request_id,
        metadata=dict(record.event_metadata or {}),
        previous_hash=record.previous_hash,
        entry_hash=record.entry_hash,
        occurred_at=record.occurred_at,
    )


def audit_to_record(entity: AuditEvent) -> AuditEventRecord:
    if entity.occurred_at is None:  # pragma: no cover - seal() always sets it
        raise ValueError("An audit event must be sealed before it is persisted.")
    return AuditEventRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        sequence=entity.sequence,
        action=entity.action,
        actor_type=entity.actor_type.value,
        actor_user_id=entity.actor_user_id,
        actor_label=entity.actor_label,
        resource_type=entity.resource_type,
        resource_id=entity.resource_id,
        outcome=entity.outcome.value,
        ip_address=entity.ip_address,
        user_agent=entity.user_agent,
        request_id=entity.request_id,
        event_metadata=entity.metadata,
        previous_hash=entity.previous_hash,
        entry_hash=entity.entry_hash,
        occurred_at=entity.occurred_at,
    )


# --- Findings -----------------------------------------------------------------------


def finding_to_domain(record: FindingRecord) -> Finding:
    return Finding(
        id=record.id,
        organization_id=record.organization_id,
        application_id=record.application_id,
        identity_hash=record.identity_hash,
        rule_key=record.rule_key,
        title=record.title,
        severity=Severity(record.severity),
        confidence=Confidence(record.confidence),
        sink_signature=record.sink_signature,
        source_kind=record.source_kind,
        stack_hash=record.stack_hash,
        status=FindingStatus(record.status),
        risk_score=float(record.risk_score),
        risk_factors=tuple(
            (str(f["name"]), float(f["delta"]), str(f["reason"])) for f in record.risk_factors
        ),
        occurrence_count=record.occurrence_count,
        suppressed_occurrence_count=record.suppressed_occurrence_count,
        would_block_count=record.would_block_count,
        environments_seen=tuple(record.environments_seen),
        route_templates=tuple(record.route_templates),
        first_seen_at=record.first_seen_at,
        last_seen_at=record.last_seen_at,
        remediated_at=record.remediated_at,
        regressed=record.regressed,
        accepted_until=record.accepted_until,
        triage_note=record.triage_note,
        triaged_by=record.triaged_by,
        cwe_id=record.cwe_id,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def finding_to_record(entity: Finding) -> FindingRecord:
    record = FindingRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        application_id=entity.application_id,
        identity_hash=entity.identity_hash,
        rule_key=entity.rule_key,
        sink_signature=entity.sink_signature,
        source_kind=entity.source_kind,
        stack_hash=entity.stack_hash,
        cwe_id=entity.cwe_id,
    )
    apply_finding_to_record(entity, record)
    return record


def apply_finding_to_record(entity: Finding, record: FindingRecord) -> None:
    """Copy the mutable half of a finding onto its row.

    Identity, rule and sink are deliberately absent: they are what the row *is*, and a
    pipeline that could rewrite them would silently merge two different defects into one.
    """
    record.title = entity.title
    record.severity = entity.severity.value
    record.confidence = entity.confidence.value
    record.status = entity.status.value
    record.risk_score = entity.risk_score
    record.risk_factors = [
        {"name": name, "delta": round(delta, 3), "reason": reason}
        for name, delta, reason in entity.risk_factors
    ]
    record.occurrence_count = entity.occurrence_count
    record.suppressed_occurrence_count = entity.suppressed_occurrence_count
    record.would_block_count = entity.would_block_count
    record.environments_seen = list(entity.environments_seen)
    record.route_templates = list(entity.route_templates)
    record.first_seen_at = entity.first_seen_at
    record.last_seen_at = entity.last_seen_at
    record.remediated_at = entity.remediated_at
    record.regressed = entity.regressed
    record.accepted_until = entity.accepted_until
    record.triage_note = entity.triage_note
    record.triaged_by = entity.triaged_by


def occurrence_to_domain(record: OccurrenceRecord) -> Occurrence:
    return Occurrence(
        id=record.id,
        organization_id=record.organization_id,
        finding_id=record.finding_id,
        environment=record.environment,
        trace_id=record.trace_id,
        request_method=record.request_method,
        request_path=record.request_path,
        route_template=record.route_template,
        sink_argument=record.sink_argument,
        tainted_ranges=tuple(
            (int(r["start"]), int(r["length"]), str(r["source"]), str(r["source_name"]))
            for r in record.tainted_ranges
        ),
        stack_frames=tuple(
            (
                str(f["declaring_class"]),
                str(f["method_name"]),
                int(f["line_number"]),
                bool(f["application_code"]),
            )
            for f in record.stack_frames
        ),
        remote_address=str(record.remote_address or ""),
        attack_detected=record.attack_detected,
        observed_at=record.observed_at,
        created_at=record.created_at,
    )


def occurrence_to_record(entity: Occurrence) -> OccurrenceRecord:
    return OccurrenceRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        finding_id=entity.finding_id,
        environment=entity.environment,
        trace_id=entity.trace_id,
        request_method=entity.request_method,
        request_path=entity.request_path,
        route_template=entity.route_template,
        sink_argument=entity.sink_argument,
        tainted_ranges=[
            {"start": s, "length": length, "source": source, "source_name": name}
            for s, length, source, name in entity.tainted_ranges
        ],
        stack_frames=[
            {
                "declaring_class": declaring_class,
                "method_name": method,
                "line_number": line,
                "application_code": is_app,
            }
            for declaring_class, method, line, is_app in entity.stack_frames
        ],
        remote_address=entity.remote_address or None,
        attack_detected=entity.attack_detected,
        observed_at=entity.observed_at,
    )


# --- Rule settings ------------------------------------------------------------------


def rule_settings_to_domain(record: TenantRuleSettingsRecord) -> TenantRuleSettings:
    return TenantRuleSettings(
        id=record.id,
        organization_id=record.organization_id,
        disabled=dict(record.disabled),
        updated_at=record.updated_at,
    )


def rule_settings_to_record(entity: TenantRuleSettings) -> TenantRuleSettingsRecord:
    return TenantRuleSettingsRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        disabled=dict(entity.disabled),
    )


# --- AI Analysis --------------------------------------------------------------------


def ai_analysis_to_domain(record: AiAnalysisRecord) -> AiAnalysis:
    return AiAnalysis(
        id=record.id,
        organization_id=record.organization_id,
        finding_id=record.finding_id,
        kind=AnalysisKind(record.kind),
        summary=record.summary,
        content=record.content,
        status=AnalysisStatus(record.status),
        model=record.model,
        prompt_hash=record.prompt_hash,
        input_tokens=record.input_tokens,
        output_tokens=record.output_tokens,
        reviewed_by=record.reviewed_by,
        review_note=record.review_note,
        failure_reason=record.failure_reason,
        created_at=record.created_at,
        reviewed_at=record.reviewed_at,
    )


def ai_analysis_to_record(entity: AiAnalysis) -> AiAnalysisRecord:
    return AiAnalysisRecord(
        id=entity.id,
        organization_id=entity.organization_id,
        finding_id=entity.finding_id,
        kind=entity.kind.value,
        summary=entity.summary,
        content=entity.content,
        status=entity.status.value,
        model=entity.model,
        prompt_hash=entity.prompt_hash,
        input_tokens=entity.input_tokens,
        output_tokens=entity.output_tokens,
        reviewed_by=entity.reviewed_by,
        review_note=entity.review_note,
        failure_reason=entity.failure_reason,
        reviewed_at=entity.reviewed_at,
    )
