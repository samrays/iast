"""Ports — the interfaces the domain and application layers depend on.

These are ``typing.Protocol`` definitions, so adapters in ``infrastructure`` satisfy them
structurally without importing anything from here. That keeps the dependency arrow pointing
inward (ADR-0002) and lets tests substitute in-memory fakes with no inheritance ceremony.
"""

from __future__ import annotations

from datetime import datetime
from types import TracebackType
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from .entities import (
    Agent,
    ApiKey,
    Application,
    ApplicationEnvironment,
    AuditEvent,
    License,
    Membership,
    MfaCredential,
    Organization,
    Role,
    Session,
    User,
)
from .entities.ai import AiAnalysis
from .entities.findings import Finding, Occurrence
from .entities.rules import RuleBundle, TenantRuleSettings
from .value_objects import ApiKeyPrefix, EmailAddress, Slug, TokenHash

# --- Infrastructure services ---------------------------------------------------------


@runtime_checkable
class Clock(Protocol):
    """Time, injected so that every expiry rule is testable without sleeping."""

    def now(self) -> datetime: ...


@runtime_checkable
class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password: str, password_hash: str) -> bool: ...

    def needs_rehash(self, password_hash: str) -> bool:
        """True when the hash was produced with weaker parameters than current policy."""
        ...

    def dummy_verify(self) -> None:
        """Burn the same CPU as a real verify.

        Called when no user matches the submitted address, so that response time does not
        reveal whether an account exists (threat T-07).
        """
        ...


@runtime_checkable
class TokenGenerator(Protocol):
    def generate(self) -> tuple[str, TokenHash]:
        """Return a fresh high-entropy token and the hash to store for it."""
        ...

    def hash(self, token: str) -> TokenHash: ...


@runtime_checkable
class AccessTokenCodec(Protocol):
    """Issues and verifies the short-lived access JWT (ADR-0006)."""

    def issue(
        self,
        *,
        subject: UUID,
        organization_id: UUID,
        session_id: UUID,
        permissions: frozenset[str],
        mfa_satisfied: bool,
        ttl_seconds: int,
        now: datetime,
    ) -> tuple[str, datetime]: ...

    def issue_challenge(
        self, *, subject: UUID, organization_id: UUID, ttl_seconds: int, now: datetime, purpose: str
    ) -> str:
        """Issue a narrow-audience token used only to complete an MFA or reset flow."""
        ...

    def decode(self, token: str, *, audience: str) -> dict[str, Any]:
        """Verify signature, expiry, issuer and audience. Raise ``TokenError`` otherwise."""
        ...


@runtime_checkable
class SecretCipher(Protocol):
    """Authenticated encryption for secrets stored at rest, such as TOTP seeds."""

    def encrypt(self, plaintext: str) -> str: ...

    def decrypt(self, ciphertext: str) -> str: ...


@runtime_checkable
class TotpService(Protocol):
    def generate_secret(self) -> str: ...

    def provisioning_uri(self, secret: str, *, account: str, issuer: str) -> str: ...

    def verify(self, secret: str, code: str, *, now: datetime) -> bool: ...


# --- Repositories --------------------------------------------------------------------


@runtime_checkable
class OrganizationRepository(Protocol):
    async def add(self, organization: Organization) -> Organization: ...

    async def get(self, organization_id: UUID) -> Organization | None: ...

    async def get_by_slug(self, slug: Slug) -> Organization | None: ...

    async def update(self, organization: Organization) -> Organization: ...

    async def slug_exists(self, slug: Slug) -> bool: ...


@runtime_checkable
class LicenseRepository(Protocol):
    async def add(self, license_: License) -> License: ...

    async def get_for_organization(self, organization_id: UUID) -> License | None: ...


@runtime_checkable
class UserRepository(Protocol):
    async def add(self, user: User) -> User: ...

    async def get(self, user_id: UUID) -> User | None: ...

    async def get_by_email(self, email: EmailAddress) -> User | None: ...

    async def update(self, user: User) -> User: ...

    async def email_exists(self, email: EmailAddress) -> bool: ...


@runtime_checkable
class MfaCredentialRepository(Protocol):
    async def add(self, credential: MfaCredential) -> MfaCredential: ...

    async def add_many(self, credentials: list[MfaCredential]) -> None: ...

    async def get_totp(
        self, user_id: UUID, *, confirmed: bool | None = None
    ) -> MfaCredential | None: ...

    async def list_recovery_codes(self, user_id: UUID) -> list[MfaCredential]: ...

    async def update(self, credential: MfaCredential) -> MfaCredential: ...

    async def delete_for_user(self, user_id: UUID) -> None: ...


@runtime_checkable
class SessionRepository(Protocol):
    async def add(self, session: Session) -> Session: ...

    async def get_by_id(self, session_id: UUID) -> Session | None: ...

    async def get_by_token_hash(self, token_hash: TokenHash) -> Session | None: ...

    async def update(self, session: Session) -> Session: ...

    async def revoke_family(self, family_id: UUID, *, now: datetime, reason: str) -> int:
        """Revoke every session in a family. Returns the number revoked."""
        ...

    async def revoke_all_for_user(
        self, user_id: UUID, *, now: datetime, reason: str, except_session_id: UUID | None = None
    ) -> int: ...

    async def count_active_for_user(self, user_id: UUID, *, now: datetime) -> int: ...

    async def list_active_for_user(self, user_id: UUID, *, now: datetime) -> list[Session]: ...


# --- Tenant-scoped repositories ------------------------------------------------------
#
# Every method below is implicitly filtered to the organization the repository was
# constructed with. There is deliberately no method that can return another tenant's row
# (ADR-0003).


@runtime_checkable
class TenantScoped(Protocol):
    @property
    def organization_id(self) -> UUID: ...


@runtime_checkable
class MembershipRepository(TenantScoped, Protocol):
    async def add(self, membership: Membership) -> Membership: ...

    async def get(self, membership_id: UUID) -> Membership | None: ...

    async def get_for_user(self, user_id: UUID) -> Membership | None: ...

    async def list_all(
        self, *, limit: int, cursor: str | None
    ) -> tuple[list[Membership], str | None]: ...

    async def update(self, membership: Membership) -> Membership: ...

    async def delete(self, membership_id: UUID) -> None: ...

    async def count(self) -> int: ...

    async def count_owners(self) -> int: ...


@runtime_checkable
class RoleRepository(TenantScoped, Protocol):
    async def add(self, role: Role) -> Role: ...

    async def add_many(self, roles: list[Role]) -> list[Role]: ...

    async def get(self, role_id: UUID) -> Role | None: ...

    async def get_by_name(self, name: str) -> Role | None: ...

    async def list_all(self) -> list[Role]: ...

    async def get_many(self, role_ids: list[UUID]) -> list[Role]: ...

    async def update(self, role: Role) -> Role: ...

    async def delete(self, role_id: UUID) -> None: ...

    async def count_memberships_using(self, role_id: UUID) -> int: ...


@runtime_checkable
class ApiKeyRepository(TenantScoped, Protocol):
    async def add(self, api_key: ApiKey) -> ApiKey: ...

    async def get(self, api_key_id: UUID) -> ApiKey | None: ...

    async def list_all(self) -> list[ApiKey]: ...

    async def update(self, api_key: ApiKey) -> ApiKey: ...


@runtime_checkable
class ApiKeyLookup(Protocol):
    """Untenanted lookup used during authentication, before a tenant is known.

    Separated from :class:`ApiKeyRepository` precisely so that the tenant-scoped interface
    keeps its guarantee: this is the one place a key is fetched without an organization,
    and it exists only to *discover* which organization the caller belongs to.
    """

    async def get_by_prefix(self, prefix: ApiKeyPrefix) -> ApiKey | None: ...

    async def touch(self, api_key_id: UUID, now: datetime) -> None: ...


@runtime_checkable
class ApplicationRepository(TenantScoped, Protocol):
    async def add(self, application: Application) -> Application: ...

    async def get(self, application_id: UUID) -> Application | None: ...

    async def get_by_slug(self, slug: Slug) -> Application | None: ...

    async def list_all(
        self,
        *,
        limit: int,
        cursor: str | None,
        search: str | None = None,
        tags: list[str] | None = None,
    ) -> tuple[list[Application], str | None]: ...

    async def update(self, application: Application) -> Application: ...

    async def delete(self, application_id: UUID) -> None: ...

    async def count(self) -> int: ...


@runtime_checkable
class EnvironmentRepository(TenantScoped, Protocol):
    async def add(self, environment: ApplicationEnvironment) -> ApplicationEnvironment: ...

    async def get(self, environment_id: UUID) -> ApplicationEnvironment | None: ...

    async def list_for_application(self, application_id: UUID) -> list[ApplicationEnvironment]: ...

    async def find(self, application_id: UUID, kind: str) -> ApplicationEnvironment | None: ...

    async def update(self, environment: ApplicationEnvironment) -> ApplicationEnvironment: ...


@runtime_checkable
class AgentRepository(TenantScoped, Protocol):
    async def add(self, agent: Agent) -> Agent: ...

    async def get(self, agent_id: UUID) -> Agent | None: ...

    async def get_by_fingerprint(self, fingerprint: str) -> Agent | None: ...

    async def list_all(
        self, *, limit: int, cursor: str | None, status: str | None = None
    ) -> tuple[list[Agent], str | None]: ...

    async def update(self, agent: Agent) -> Agent: ...

    async def count(self) -> int: ...


@runtime_checkable
class AuditRepository(TenantScoped, Protocol):
    async def append(self, event: AuditEvent) -> AuditEvent:
        """Seal and persist an entry, assigning the next sequence number atomically."""
        ...

    async def list_all(
        self,
        *,
        limit: int,
        cursor: str | None,
        action: str | None = None,
        actor_user_id: UUID | None = None,
        occurred_after: datetime | None = None,
    ) -> tuple[list[AuditEvent], str | None]: ...

    async def verify_chain(self, *, limit: int | None = None) -> tuple[bool, int, int | None]:
        """Walk the chain and return ``(intact, entries_checked, first_broken_sequence)``."""
        ...


# --- Unit of work --------------------------------------------------------------------


@runtime_checkable
class FindingRepository(Protocol):
    """Findings, their evidence and their triage thread.

    Tenant-scoped: obtained only after ``bind_tenant``, so every query here already carries
    the organization predicate and rides the row-level-security policy.
    """

    async def resolve_agent_context(self, agent_id: str) -> Any | None:
        """Which application and environment an agent reports for, or None if unregistered."""
        ...

    async def get(self, finding_id: UUID) -> Finding | None: ...

    async def get_by_identity(self, identity_hash: str) -> Finding | None: ...

    async def upsert(self, finding: Finding) -> Finding: ...

    async def list_all(
        self,
        *,
        limit: int,
        cursor: str | None,
        statuses: list[str] | None = None,
        severities: list[str] | None = None,
        rule_key: str | None = None,
        application_id: UUID | None = None,
        environment: str | None = None,
        search: str | None = None,
    ) -> tuple[list[Finding], str | None]: ...

    async def list_expired_acceptances(self, now: datetime) -> list[Finding]: ...

    async def add_occurrence(self, occurrence: Occurrence) -> None: ...

    async def latest_occurrence_at(self, finding_id: UUID) -> datetime | None: ...

    async def list_occurrences(self, finding_id: UUID, *, limit: int = 20) -> list[Occurrence]: ...

    async def add_comment(
        self,
        *,
        finding_id: UUID,
        organization_id: UUID,
        author_id: UUID | None,
        author_label: str,
        body: str,
        status_from: str | None = None,
        status_to: str | None = None,
    ) -> dict[str, Any]: ...

    async def list_comments(self, finding_id: UUID) -> list[dict[str, Any]]: ...


@runtime_checkable
class AiAnalysisRepository(TenantScoped, Protocol):
    """AI analyses generated for findings."""

    async def add(self, analysis: AiAnalysis) -> AiAnalysis: ...

    async def get(self, analysis_id: UUID) -> AiAnalysis | None: ...

    async def list_for_finding(self, finding_id: UUID) -> list[AiAnalysis]: ...

    async def update(self, analysis: AiAnalysis) -> AiAnalysis: ...


class RuleSettingsRepository(Protocol):
    """One organization's rule opt-outs.

    ``get`` never returns None: a tenant who has never changed anything has every rule on, and
    representing that as an absent row would make every caller handle a null that means "the
    default".
    """

    async def get(self) -> TenantRuleSettings: ...

    async def save(self, settings: TenantRuleSettings) -> TenantRuleSettings: ...


class RuleBundleRepository(Protocol):
    """Installed catalogue bundles.

    Not tenant-scoped, unlike everything else obtained from the unit of work: the catalogue is
    published by the vendor, and a tenant-writable rule set would let one organization decide
    what the engine detects for everyone.
    """

    async def current(self) -> tuple[RuleBundle, int] | None: ...

    async def installed_version(self) -> int | None: ...

    async def install(self, bundle: RuleBundle, signature: bytes) -> None: ...


class UnitOfWork(Protocol):
    """Transaction boundary.

    A use case opens exactly one unit of work. Repositories obtained from it share the same
    transaction, which is also where the ``app.current_organization_id`` setting used by
    row-level security is established.
    """

    # Declared as read-only properties, not mutable attributes: a mutable protocol
    # attribute is invariant, so an adapter returning a concrete repository type would
    # fail the structural check even though it is a perfectly good implementation.
    @property
    def organizations(self) -> OrganizationRepository: ...

    @property
    def licenses(self) -> LicenseRepository: ...

    @property
    def users(self) -> UserRepository: ...

    @property
    def mfa_credentials(self) -> MfaCredentialRepository: ...

    @property
    def sessions(self) -> SessionRepository: ...

    @property
    def api_key_lookup(self) -> ApiKeyLookup: ...

    @property
    def rule_bundles(self) -> RuleBundleRepository:
        """Available without ``bind_tenant`` — the catalogue is not tenant data."""
        ...

    @property
    def findings(self) -> FindingRepository:
        """Available only after ``bind_tenant``."""
        ...

    @property
    def rule_settings(self) -> RuleSettingsRepository:
        """Available only after ``bind_tenant``."""
        ...

    @property
    def ai_analyses(self) -> AiAnalysisRepository:
        """Available only after ``bind_tenant``."""
        ...

    async def __aenter__(self) -> UnitOfWork: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...

    async def bind_tenant(self, organization_id: UUID) -> None:
        """Scope this transaction to a tenant and enable the scoped repositories."""
        ...

    async def find_active_organizations_for_user(self, user_id: UUID) -> list[Organization]:
        """Organizations the user is an active member of.

        Cross-tenant by necessity — it answers "which tenants may this person sign in to",
        a question that exists before a tenant is known. It returns organizations only,
        never tenant-owned data, so it cannot leak one tenant's contents to another.
        """
        ...

    @property
    def memberships(self) -> MembershipRepository: ...

    @property
    def roles(self) -> RoleRepository: ...

    @property
    def api_keys(self) -> ApiKeyRepository: ...

    @property
    def applications(self) -> ApplicationRepository: ...

    @property
    def environments(self) -> EnvironmentRepository: ...

    @property
    def agents(self) -> AgentRepository: ...

    @property
    def audit(self) -> AuditRepository: ...
