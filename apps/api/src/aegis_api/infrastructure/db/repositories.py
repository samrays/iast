"""SQLAlchemy repository adapters.

Two families live here:

* **Global repositories** — organizations, users, MFA credentials and sessions. These are
  not tenant-owned, or (in the case of sessions) are looked up by a high-entropy secret
  before any tenant is known.
* **Tenant-scoped repositories** — everything else. Each is constructed with an
  organization id and injects that predicate into every statement. There is deliberately
  no method that can produce an unscoped query (ADR-0003).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypeVar
from uuid import UUID, uuid4

from sqlalchemy import Select, and_, delete, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...application.findings import AgentContext
from ...domain.entities import (
    Agent,
    ApiKey,
    Application,
    ApplicationEnvironment,
    AuditEvent,
    Criticality,
    EnvironmentKind,
    Finding,
    License,
    Membership,
    MfaCredential,
    MfaKind,
    Occurrence,
    Organization,
    Role,
    Session,
    User,
)
from ...domain.entities.audit import GENESIS_HASH
from ...domain.entities.rules import TenantRuleSettings
from ...domain.value_objects import ApiKeyPrefix, EmailAddress, Slug, TokenHash
from . import mappers as m
from .models import (
    AgentRecord,
    ApiKeyRecord,
    ApplicationEnvironmentRecord,
    ApplicationRecord,
    AuditEventRecord,
    FindingCommentRecord,
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
    membership_roles,
)
from .pagination import decode_cursor, decode_score_cursor, encode_cursor, encode_score_cursor

R = TypeVar("R")


class _Repository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session


class _TenantRepository(_Repository):
    """Base for repositories bound to one tenant."""

    def __init__(self, session: AsyncSession, organization_id: UUID) -> None:
        super().__init__(session)
        self._organization_id = organization_id

    @property
    def organization_id(self) -> UUID:
        return self._organization_id


# --- Global repositories --------------------------------------------------------------


class SqlOrganizationRepository(_Repository):
    async def add(self, organization: Organization) -> Organization:
        record = m.organization_to_record(organization)
        self._session.add(record)
        await self._session.flush()
        return m.organization_to_domain(record)

    async def get(self, organization_id: UUID) -> Organization | None:
        record = await self._session.get(OrganizationRecord, organization_id)
        return m.organization_to_domain(record) if record else None

    async def get_by_slug(self, slug: Slug) -> Organization | None:
        stmt = select(OrganizationRecord).where(OrganizationRecord.slug == slug.value)
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.organization_to_domain(record) if record else None

    async def update(self, organization: Organization) -> Organization:
        record = await self._session.get(OrganizationRecord, organization.id)
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Organization {organization.id} does not exist.")
        m.apply_organization(record, organization)
        await self._session.flush()
        return m.organization_to_domain(record)

    async def slug_exists(self, slug: Slug) -> bool:
        stmt = (
            select(func.count())
            .select_from(OrganizationRecord)
            .where(OrganizationRecord.slug == slug.value)
        )
        return bool((await self._session.execute(stmt)).scalar_one())


class SqlLicenseRepository(_Repository):
    async def add(self, license_: License) -> License:
        record = m.license_to_record(license_)
        self._session.add(record)
        await self._session.flush()
        return m.license_to_domain(record)

    async def get_for_organization(self, organization_id: UUID) -> License | None:
        stmt = select(LicenseRecord).where(LicenseRecord.organization_id == organization_id)
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.license_to_domain(record) if record else None


class SqlUserRepository(_Repository):
    async def add(self, user: User) -> User:
        record = m.user_to_record(user)
        self._session.add(record)
        await self._session.flush()
        return m.user_to_domain(record)

    async def get(self, user_id: UUID) -> User | None:
        record = await self._session.get(UserRecord, user_id)
        return m.user_to_domain(record) if record else None

    async def get_by_email(self, email: EmailAddress) -> User | None:
        stmt = select(UserRecord).where(UserRecord.email == email.value)
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.user_to_domain(record) if record else None

    async def update(self, user: User) -> User:
        record = await self._session.get(UserRecord, user.id)
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"User {user.id} does not exist.")
        m.apply_user(record, user)
        await self._session.flush()
        return m.user_to_domain(record)

    async def email_exists(self, email: EmailAddress) -> bool:
        stmt = select(func.count()).select_from(UserRecord).where(UserRecord.email == email.value)
        return bool((await self._session.execute(stmt)).scalar_one())


class SqlMfaCredentialRepository(_Repository):
    async def add(self, credential: MfaCredential) -> MfaCredential:
        record = m.mfa_to_record(credential)
        self._session.add(record)
        await self._session.flush()
        return m.mfa_to_domain(record)

    async def add_many(self, credentials: list[MfaCredential]) -> None:
        self._session.add_all([m.mfa_to_record(c) for c in credentials])
        await self._session.flush()

    async def get_totp(
        self, user_id: UUID, *, confirmed: bool | None = None
    ) -> MfaCredential | None:
        stmt = select(MfaCredentialRecord).where(
            MfaCredentialRecord.user_id == user_id,
            MfaCredentialRecord.kind == MfaKind.TOTP.value,
        )
        if confirmed is not None:
            stmt = stmt.where(MfaCredentialRecord.confirmed.is_(confirmed))
        record = (await self._session.execute(stmt.limit(1))).scalar_one_or_none()
        return m.mfa_to_domain(record) if record else None

    async def list_recovery_codes(self, user_id: UUID) -> list[MfaCredential]:
        stmt = select(MfaCredentialRecord).where(
            MfaCredentialRecord.user_id == user_id,
            MfaCredentialRecord.kind == MfaKind.RECOVERY_CODE.value,
            MfaCredentialRecord.consumed_at.is_(None),
        )
        return [m.mfa_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

    async def update(self, credential: MfaCredential) -> MfaCredential:
        record = await self._session.get(MfaCredentialRecord, credential.id)
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"MFA credential {credential.id} does not exist.")
        m.apply_mfa(record, credential)
        await self._session.flush()
        return m.mfa_to_domain(record)

    async def delete_for_user(self, user_id: UUID) -> None:
        await self._session.execute(
            delete(MfaCredentialRecord).where(MfaCredentialRecord.user_id == user_id)
        )


class SqlSessionRepository(_Repository):
    async def add(self, session: Session) -> Session:
        record = m.session_to_record(session)
        self._session.add(record)
        await self._session.flush()
        return m.session_to_domain(record)

    async def get_by_id(self, session_id: UUID) -> Session | None:
        record = await self._session.get(SessionRecord, session_id)
        return m.session_to_domain(record) if record else None

    async def get_by_token_hash(self, token_hash: TokenHash) -> Session | None:
        stmt = select(SessionRecord).where(SessionRecord.refresh_token_hash == token_hash.value)
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.session_to_domain(record) if record else None

    async def update(self, session: Session) -> Session:
        record = await self._session.get(SessionRecord, session.id)
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Session {session.id} does not exist.")
        m.apply_session(record, session)
        await self._session.flush()
        return m.session_to_domain(record)

    async def revoke_family(self, family_id: UUID, *, now: datetime, reason: str) -> int:
        """Revoke every session sharing a family id.

        A bulk UPDATE rather than a load-and-save loop: reuse detection must be fast and
        atomic, and there is no per-row logic to apply.
        """
        stmt = (
            update(SessionRecord)
            .where(SessionRecord.family_id == family_id, SessionRecord.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
        )
        result = await self._session.execute(stmt)
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    async def revoke_all_for_user(
        self, user_id: UUID, *, now: datetime, reason: str, except_session_id: UUID | None = None
    ) -> int:
        stmt = (
            update(SessionRecord)
            .where(SessionRecord.user_id == user_id, SessionRecord.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
        )
        if except_session_id is not None:
            stmt = stmt.where(SessionRecord.id != except_session_id)
        result = await self._session.execute(stmt)
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    async def count_active_for_user(self, user_id: UUID, *, now: datetime) -> int:
        stmt = (
            select(func.count())
            .select_from(SessionRecord)
            .where(
                SessionRecord.user_id == user_id,
                SessionRecord.revoked_at.is_(None),
                SessionRecord.rotated_at.is_(None),
                SessionRecord.expires_at > now,
            )
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def list_active_for_user(self, user_id: UUID, *, now: datetime) -> list[Session]:
        stmt = select(SessionRecord).where(
            SessionRecord.user_id == user_id,
            SessionRecord.revoked_at.is_(None),
            SessionRecord.rotated_at.is_(None),
            SessionRecord.expires_at > now,
        )
        return [m.session_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]


class SqlApiKeyLookup(_Repository):
    """Pre-tenant lookup of an API key by its public prefix.

    Authenticating an API key is the act that *discovers* the tenant, so it cannot be
    tenant-scoped. ``api_keys`` is RLS-protected, so these two statements raise the
    ``app.rls_bypass`` flag the policy recognizes and lower it immediately. Both are keyed
    by a unique 12-character prefix and neither returns tenant-owned data — the Argon2
    verification of the secret still stands between a caller and any access.
    """

    async def _with_bypass(self, statement: Any) -> Any:
        await self._session.execute(text("SELECT set_config('app.rls_bypass', 'on', true)"))
        try:
            return await self._session.execute(statement)
        finally:
            await self._session.execute(text("SELECT set_config('app.rls_bypass', 'off', true)"))

    async def get_by_prefix(self, prefix: ApiKeyPrefix) -> ApiKey | None:
        stmt = select(ApiKeyRecord).where(ApiKeyRecord.prefix == prefix.value)
        record = (await self._with_bypass(stmt)).scalar_one_or_none()
        return m.api_key_to_domain(record) if record else None

    async def touch(self, api_key_id: UUID, now: datetime) -> None:
        await self._with_bypass(
            update(ApiKeyRecord).where(ApiKeyRecord.id == api_key_id).values(last_used_at=now)
        )


# --- Tenant-scoped repositories --------------------------------------------------------


class SqlMembershipRepository(_TenantRepository):
    def _scoped(self) -> Select[tuple[MembershipRecord]]:
        return select(MembershipRecord).where(
            MembershipRecord.organization_id == self._organization_id
        )

    async def add(self, membership: Membership) -> Membership:
        record = m.membership_to_record(membership)
        self._session.add(record)
        await self._session.flush()
        for role in membership.roles:
            await self._session.execute(
                membership_roles.insert().values(membership_id=record.id, role_id=role.id)
            )
        await self._session.refresh(record, ["roles"])
        return m.membership_to_domain(record)

    async def get(self, membership_id: UUID) -> Membership | None:
        stmt = self._scoped().where(MembershipRecord.id == membership_id)
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.membership_to_domain(record) if record else None

    async def get_for_user(self, user_id: UUID) -> Membership | None:
        stmt = self._scoped().where(MembershipRecord.user_id == user_id)
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.membership_to_domain(record) if record else None

    async def list_all(
        self, *, limit: int, cursor: str | None
    ) -> tuple[list[Membership], str | None]:
        stmt = self._scoped().order_by(MembershipRecord.created_at, MembershipRecord.id)
        if cursor:
            created_at, row_id = decode_cursor(cursor)
            stmt = stmt.where(
                or_(
                    MembershipRecord.created_at > created_at,
                    (MembershipRecord.created_at == created_at) & (MembershipRecord.id > row_id),
                )
            )
        records = list((await self._session.execute(stmt.limit(limit + 1))).scalars())
        return _paginate(records, limit, m.membership_to_domain)

    async def update(self, membership: Membership) -> Membership:
        record = (
            await self._session.execute(self._scoped().where(MembershipRecord.id == membership.id))
        ).scalar_one_or_none()
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Membership {membership.id} does not exist.")
        record.status = membership.status.value
        record.joined_at = membership.joined_at
        await self._session.execute(
            membership_roles.delete().where(membership_roles.c.membership_id == record.id)
        )
        for role in membership.roles:
            await self._session.execute(
                membership_roles.insert().values(membership_id=record.id, role_id=role.id)
            )
        await self._session.flush()
        await self._session.refresh(record, ["roles"])
        return m.membership_to_domain(record)

    async def delete(self, membership_id: UUID) -> None:
        await self._session.execute(
            delete(MembershipRecord).where(
                MembershipRecord.id == membership_id,
                MembershipRecord.organization_id == self._organization_id,
            )
        )

    async def count(self) -> int:
        stmt = (
            select(func.count())
            .select_from(MembershipRecord)
            .where(MembershipRecord.organization_id == self._organization_id)
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def count_owners(self) -> int:
        """How many members hold the system Owner role.

        Used to stop the last Owner being demoted or removed, which would leave the
        organization unadministrable.
        """
        stmt = (
            select(func.count(func.distinct(MembershipRecord.id)))
            .select_from(MembershipRecord)
            .join(membership_roles, membership_roles.c.membership_id == MembershipRecord.id)
            .join(RoleRecord, RoleRecord.id == membership_roles.c.role_id)
            .where(
                MembershipRecord.organization_id == self._organization_id,
                RoleRecord.is_system.is_(True),
                RoleRecord.name == "Owner",
            )
        )
        return int((await self._session.execute(stmt)).scalar_one())


class SqlRoleRepository(_TenantRepository):
    def _scoped(self) -> Select[tuple[RoleRecord]]:
        return select(RoleRecord).where(RoleRecord.organization_id == self._organization_id)

    async def add(self, role: Role) -> Role:
        record = m.role_to_record(role)
        self._session.add(record)
        await self._session.flush()
        return m.role_to_domain(record)

    async def add_many(self, roles: list[Role]) -> list[Role]:
        records = [m.role_to_record(r) for r in roles]
        self._session.add_all(records)
        await self._session.flush()
        return [m.role_to_domain(r) for r in records]

    async def get(self, role_id: UUID) -> Role | None:
        record = (
            await self._session.execute(self._scoped().where(RoleRecord.id == role_id))
        ).scalar_one_or_none()
        return m.role_to_domain(record) if record else None

    async def get_by_name(self, name: str) -> Role | None:
        record = (
            await self._session.execute(self._scoped().where(RoleRecord.name == name))
        ).scalar_one_or_none()
        return m.role_to_domain(record) if record else None

    async def list_all(self) -> list[Role]:
        stmt = self._scoped().order_by(RoleRecord.is_system.desc(), RoleRecord.name)
        return [m.role_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

    async def get_many(self, role_ids: list[UUID]) -> list[Role]:
        if not role_ids:
            return []
        stmt = self._scoped().where(RoleRecord.id.in_(role_ids))
        return [m.role_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

    async def update(self, role: Role) -> Role:
        record = (
            await self._session.execute(self._scoped().where(RoleRecord.id == role.id))
        ).scalar_one_or_none()
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Role {role.id} does not exist.")
        m.apply_role(record, role)
        await self._session.flush()
        return m.role_to_domain(record)

    async def delete(self, role_id: UUID) -> None:
        await self._session.execute(
            delete(RoleRecord).where(
                RoleRecord.id == role_id, RoleRecord.organization_id == self._organization_id
            )
        )

    async def count_memberships_using(self, role_id: UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(membership_roles)
            .join(MembershipRecord, MembershipRecord.id == membership_roles.c.membership_id)
            .where(
                membership_roles.c.role_id == role_id,
                MembershipRecord.organization_id == self._organization_id,
            )
        )
        return int((await self._session.execute(stmt)).scalar_one())


class SqlApiKeyRepository(_TenantRepository):
    def _scoped(self) -> Select[tuple[ApiKeyRecord]]:
        return select(ApiKeyRecord).where(ApiKeyRecord.organization_id == self._organization_id)

    async def add(self, api_key: ApiKey) -> ApiKey:
        record = m.api_key_to_record(api_key)
        self._session.add(record)
        await self._session.flush()
        return m.api_key_to_domain(record)

    async def get(self, api_key_id: UUID) -> ApiKey | None:
        record = (
            await self._session.execute(self._scoped().where(ApiKeyRecord.id == api_key_id))
        ).scalar_one_or_none()
        return m.api_key_to_domain(record) if record else None

    async def list_all(self) -> list[ApiKey]:
        stmt = self._scoped().order_by(ApiKeyRecord.created_at.desc())
        return [m.api_key_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

    async def update(self, api_key: ApiKey) -> ApiKey:
        record = (
            await self._session.execute(self._scoped().where(ApiKeyRecord.id == api_key.id))
        ).scalar_one_or_none()
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"API key {api_key.id} does not exist.")
        m.apply_api_key(record, api_key)
        await self._session.flush()
        return m.api_key_to_domain(record)


class SqlApplicationRepository(_TenantRepository):
    def _scoped(self) -> Select[tuple[ApplicationRecord]]:
        return select(ApplicationRecord).where(
            ApplicationRecord.organization_id == self._organization_id
        )

    async def add(self, application: Application) -> Application:
        record = m.application_to_record(application)
        self._session.add(record)
        await self._session.flush()
        return m.application_to_domain(record)

    async def get(self, application_id: UUID) -> Application | None:
        record = (
            await self._session.execute(
                self._scoped().where(ApplicationRecord.id == application_id)
            )
        ).scalar_one_or_none()
        return m.application_to_domain(record) if record else None

    async def get_by_slug(self, slug: Slug) -> Application | None:
        record = (
            await self._session.execute(self._scoped().where(ApplicationRecord.slug == slug.value))
        ).scalar_one_or_none()
        return m.application_to_domain(record) if record else None

    async def list_all(
        self,
        *,
        limit: int,
        cursor: str | None,
        search: str | None = None,
        tags: list[str] | None = None,
    ) -> tuple[list[Application], str | None]:
        stmt = self._scoped().order_by(ApplicationRecord.created_at, ApplicationRecord.id)
        if search:
            pattern = f"%{search.strip().lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(ApplicationRecord.name).like(pattern),
                    ApplicationRecord.slug.like(pattern),
                )
            )
        if tags:
            stmt = stmt.where(ApplicationRecord.tags.contains([t.lower() for t in tags]))
        if cursor:
            created_at, row_id = decode_cursor(cursor)
            stmt = stmt.where(
                or_(
                    ApplicationRecord.created_at > created_at,
                    (ApplicationRecord.created_at == created_at) & (ApplicationRecord.id > row_id),
                )
            )
        records = list((await self._session.execute(stmt.limit(limit + 1))).scalars())
        return _paginate(records, limit, m.application_to_domain)

    async def update(self, application: Application) -> Application:
        record = (
            await self._session.execute(
                self._scoped().where(ApplicationRecord.id == application.id)
            )
        ).scalar_one_or_none()
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Application {application.id} does not exist.")
        m.apply_application(record, application)
        await self._session.flush()
        return m.application_to_domain(record)

    async def delete(self, application_id: UUID) -> None:
        await self._session.execute(
            delete(ApplicationRecord).where(
                ApplicationRecord.id == application_id,
                ApplicationRecord.organization_id == self._organization_id,
            )
        )

    async def count(self) -> int:
        stmt = (
            select(func.count())
            .select_from(ApplicationRecord)
            .where(ApplicationRecord.organization_id == self._organization_id)
        )
        return int((await self._session.execute(stmt)).scalar_one())


class SqlEnvironmentRepository(_TenantRepository):
    def _scoped(self) -> Select[tuple[ApplicationEnvironmentRecord]]:
        return select(ApplicationEnvironmentRecord).where(
            ApplicationEnvironmentRecord.organization_id == self._organization_id
        )

    async def add(self, environment: ApplicationEnvironment) -> ApplicationEnvironment:
        record = m.environment_to_record(environment)
        self._session.add(record)
        await self._session.flush()
        return m.environment_to_domain(record)

    async def get(self, environment_id: UUID) -> ApplicationEnvironment | None:
        record = (
            await self._session.execute(
                self._scoped().where(ApplicationEnvironmentRecord.id == environment_id)
            )
        ).scalar_one_or_none()
        return m.environment_to_domain(record) if record else None

    async def list_for_application(self, application_id: UUID) -> list[ApplicationEnvironment]:
        stmt = (
            self._scoped()
            .where(ApplicationEnvironmentRecord.application_id == application_id)
            .order_by(ApplicationEnvironmentRecord.kind)
        )
        return [m.environment_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

    async def find(self, application_id: UUID, kind: str) -> ApplicationEnvironment | None:
        stmt = self._scoped().where(
            ApplicationEnvironmentRecord.application_id == application_id,
            ApplicationEnvironmentRecord.kind == kind,
        )
        record = (await self._session.execute(stmt)).scalar_one_or_none()
        return m.environment_to_domain(record) if record else None

    async def update(self, environment: ApplicationEnvironment) -> ApplicationEnvironment:
        record = (
            await self._session.execute(
                self._scoped().where(ApplicationEnvironmentRecord.id == environment.id)
            )
        ).scalar_one_or_none()
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Environment {environment.id} does not exist.")
        m.apply_environment(record, environment)
        await self._session.flush()
        return m.environment_to_domain(record)


class SqlAgentRepository(_TenantRepository):
    def _scoped(self) -> Select[tuple[AgentRecord]]:
        return select(AgentRecord).where(AgentRecord.organization_id == self._organization_id)

    async def add(self, agent: Agent) -> Agent:
        record = m.agent_to_record(agent)
        self._session.add(record)
        await self._session.flush()
        return m.agent_to_domain(record)

    async def get(self, agent_id: UUID) -> Agent | None:
        record = (
            await self._session.execute(self._scoped().where(AgentRecord.id == agent_id))
        ).scalar_one_or_none()
        return m.agent_to_domain(record) if record else None

    async def get_by_fingerprint(self, fingerprint: str) -> Agent | None:
        record = (
            await self._session.execute(
                self._scoped().where(AgentRecord.fingerprint == fingerprint)
            )
        ).scalar_one_or_none()
        return m.agent_to_domain(record) if record else None

    async def list_all(
        self, *, limit: int, cursor: str | None, status: str | None = None
    ) -> tuple[list[Agent], str | None]:
        stmt = self._scoped().order_by(AgentRecord.created_at, AgentRecord.id)
        if status:
            stmt = stmt.where(AgentRecord.status == status)
        if cursor:
            created_at, row_id = decode_cursor(cursor)
            stmt = stmt.where(
                or_(
                    AgentRecord.created_at > created_at,
                    (AgentRecord.created_at == created_at) & (AgentRecord.id > row_id),
                )
            )
        records = list((await self._session.execute(stmt.limit(limit + 1))).scalars())
        return _paginate(records, limit, m.agent_to_domain)

    async def update(self, agent: Agent) -> Agent:
        record = (
            await self._session.execute(self._scoped().where(AgentRecord.id == agent.id))
        ).scalar_one_or_none()
        if record is None:  # pragma: no cover - callers load before updating
            raise LookupError(f"Agent {agent.id} does not exist.")
        m.apply_agent(record, agent)
        await self._session.flush()
        return m.agent_to_domain(record)

    async def count(self) -> int:
        stmt = (
            select(func.count())
            .select_from(AgentRecord)
            .where(AgentRecord.organization_id == self._organization_id)
        )
        return int((await self._session.execute(stmt)).scalar_one())


class SqlAuditRepository(_TenantRepository):
    """Append-only access to the tenant's audit chain."""

    def _scoped(self) -> Select[tuple[AuditEventRecord]]:
        return select(AuditEventRecord).where(
            AuditEventRecord.organization_id == self._organization_id
        )

    #: Namespace for the per-tenant advisory lock, so this lock cannot collide with any
    #: other advisory lock the application might take later.
    _APPEND_LOCK_NAMESPACE = 0x4165_6773  # "Aegs"

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Seal and insert, claiming the next sequence number.

        A transaction-scoped advisory lock serializes concurrent appends within the tenant.
        ``SELECT ... FOR UPDATE`` would be the obvious choice but requires the UPDATE
        privilege on ``audit_events`` — and the application role deliberately does not have
        it, so that append-only holds at the privilege level and not only via the trigger
        (threat T-11). The unique constraint on ``(organization_id, sequence)`` remains the
        backstop.
        """
        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:ns, hashtext(:org))"),
            {"ns": self._APPEND_LOCK_NAMESPACE, "org": str(self._organization_id)},
        )
        tail_stmt = self._scoped().order_by(AuditEventRecord.sequence.desc()).limit(1)
        tail = (await self._session.execute(tail_stmt)).scalar_one_or_none()
        previous_hash = tail.entry_hash if tail else GENESIS_HASH
        sequence = (tail.sequence + 1) if tail else 1

        occurred_at = event.occurred_at or _utcnow()
        event.seal(previous_hash, occurred_at, sequence)
        self._session.add(m.audit_to_record(event))
        await self._session.flush()
        return event

    async def list_all(
        self,
        *,
        limit: int,
        cursor: str | None,
        action: str | None = None,
        actor_user_id: UUID | None = None,
        occurred_after: datetime | None = None,
    ) -> tuple[list[AuditEvent], str | None]:
        # Newest first — the audit log is read as a feed, not as an archive.
        stmt = self._scoped().order_by(
            AuditEventRecord.occurred_at.desc(), AuditEventRecord.id.desc()
        )
        if action:
            stmt = stmt.where(AuditEventRecord.action == action)
        if actor_user_id:
            stmt = stmt.where(AuditEventRecord.actor_user_id == actor_user_id)
        if occurred_after:
            stmt = stmt.where(AuditEventRecord.occurred_at > occurred_after)
        if cursor:
            occurred_at, row_id = decode_cursor(cursor)
            stmt = stmt.where(
                or_(
                    AuditEventRecord.occurred_at < occurred_at,
                    (AuditEventRecord.occurred_at == occurred_at) & (AuditEventRecord.id < row_id),
                )
            )
        records = list((await self._session.execute(stmt.limit(limit + 1))).scalars())
        has_more = len(records) > limit
        page = records[:limit]
        next_cursor = (
            encode_cursor(page[-1].occurred_at, page[-1].id) if has_more and page else None
        )
        return [m.audit_to_domain(r) for r in page], next_cursor

    async def verify_chain(self, *, limit: int | None = None) -> tuple[bool, int, int | None]:
        stmt = self._scoped().order_by(AuditEventRecord.sequence)
        if limit:
            stmt = stmt.limit(limit)
        records = list((await self._session.execute(stmt)).scalars())

        expected_previous = GENESIS_HASH
        checked = 0
        for record in records:
            event = m.audit_to_domain(record)
            checked += 1
            if not event.verify(expected_previous):
                return False, checked, record.sequence
            expected_previous = event.entry_hash
        return True, checked, None


# --- helpers ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)


def _paginate(records: list[Any], limit: int, to_domain: Any) -> tuple[list[Any], str | None]:
    """Trim the sentinel row and derive the next cursor from the last kept row."""
    has_more = len(records) > limit
    page = records[:limit]
    next_cursor = encode_cursor(page[-1].created_at, page[-1].id) if has_more and page else None
    return [to_domain(r) for r in page], next_cursor


class SqlFindingRepository(_TenantRepository):
    """Findings, their evidence and the agent lookup the worker needs.

    Every query is scoped by ``organization_id`` in the WHERE clause as well as being covered
    by row-level security. Belt and braces on purpose: RLS is the backstop that survives a
    forgotten predicate, and the predicate is what keeps the query on the tenant index.
    """

    def _scoped(self) -> Select[tuple[FindingRecord]]:
        return select(FindingRecord).where(FindingRecord.organization_id == self._organization_id)

    async def resolve_agent_context(self, agent_id: str) -> AgentContext | None:
        """Which application, environment and criticality an agent reports for.

        Resolved from the control plane's own inventory rather than from anything the agent
        said. Returning ``None`` for an unregistered agent is what stops a leaked token
        inventing an application to file findings against.
        """
        try:
            identifier = UUID(agent_id)
        except (ValueError, AttributeError):
            return None

        stmt = (
            select(
                ApplicationEnvironmentRecord.application_id,
                ApplicationEnvironmentRecord.kind,
                ApplicationEnvironmentRecord.internet_facing,
                ApplicationRecord.criticality,
                ApplicationEnvironmentRecord.protection_mode,
            )
            # Explicit: without it SQLAlchemy infers the FROM from the selected columns and
            # leaves 'agents' dangling in a comma join.
            .select_from(AgentRecord)
            .join(
                ApplicationEnvironmentRecord,
                AgentRecord.application_environment_id == ApplicationEnvironmentRecord.id,
            )
            .join(
                ApplicationRecord,
                ApplicationEnvironmentRecord.application_id == ApplicationRecord.id,
            )
            .where(
                AgentRecord.id == identifier,
                AgentRecord.organization_id == self._organization_id,
            )
        )
        row = (await self._session.execute(stmt)).first()
        if row is None:
            return None
        return AgentContext(
            application_id=row[0],
            environment_kind=EnvironmentKind(row[1]),
            internet_facing=bool(row[2]),
            criticality=Criticality(row[3]),
            protection_mode=str(row[4]),
        )

    async def get_by_identity(self, identity_hash: str) -> Finding | None:
        record = (
            await self._session.execute(
                self._scoped().where(FindingRecord.identity_hash == identity_hash)
            )
        ).scalar_one_or_none()
        return m.finding_to_domain(record) if record else None

    async def get(self, finding_id: UUID) -> Finding | None:
        record = (
            await self._session.execute(self._scoped().where(FindingRecord.id == finding_id))
        ).scalar_one_or_none()
        return m.finding_to_domain(record) if record else None

    async def upsert(self, finding: Finding) -> Finding:
        """Insert a new finding, or update the one already carrying this identity.

        The identity is derived rather than assigned, so this converges: replaying an event
        stream produces increments on existing rows instead of duplicates.
        """
        existing = (
            await self._session.execute(
                self._scoped().where(FindingRecord.identity_hash == finding.identity_hash)
            )
        ).scalar_one_or_none()

        if existing is None:
            record = m.finding_to_record(finding)
            self._session.add(record)
            await self._session.flush()
            return m.finding_to_domain(record)

        m.apply_finding_to_record(finding, existing)
        await self._session.flush()
        return m.finding_to_domain(existing)

    async def add_occurrence(self, occurrence: Occurrence) -> None:
        self._session.add(m.occurrence_to_record(occurrence))
        await self._session.flush()

    async def latest_occurrence_at(self, finding_id: UUID) -> datetime | None:
        stmt = select(func.max(OccurrenceRecord.observed_at)).where(
            OccurrenceRecord.finding_id == finding_id,
            OccurrenceRecord.organization_id == self._organization_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_occurrences(self, finding_id: UUID, *, limit: int = 20) -> list[Occurrence]:
        stmt = (
            select(OccurrenceRecord)
            .where(
                OccurrenceRecord.finding_id == finding_id,
                OccurrenceRecord.organization_id == self._organization_id,
            )
            .order_by(OccurrenceRecord.observed_at.desc())
            .limit(limit)
        )
        return [m.occurrence_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

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
    ) -> tuple[list[Finding], str | None]:
        """The queue, worst first.

        Ordered by risk score descending with the id as a tiebreaker, which is what makes the
        cursor stable: two findings with the same score must always come back in the same
        order or paging would skip or repeat rows between requests.
        """
        stmt = self._scoped()
        if statuses:
            stmt = stmt.where(FindingRecord.status.in_(statuses))
        if severities:
            stmt = stmt.where(FindingRecord.severity.in_(severities))
        if rule_key:
            stmt = stmt.where(FindingRecord.rule_key == rule_key.strip().lower())
        if application_id is not None:
            stmt = stmt.where(FindingRecord.application_id == application_id)
        if environment:
            stmt = stmt.where(FindingRecord.environments_seen.contains([environment]))
        if search:
            stmt = stmt.where(func.lower(FindingRecord.title).like(f"%{search.strip().lower()}%"))

        stmt = stmt.order_by(FindingRecord.risk_score.desc(), FindingRecord.id)
        if cursor:
            score, identifier = decode_score_cursor(cursor)
            stmt = stmt.where(
                or_(
                    FindingRecord.risk_score < score,
                    and_(
                        FindingRecord.risk_score == score,
                        FindingRecord.id > identifier,
                    ),
                )
            )

        records = list((await self._session.execute(stmt.limit(limit + 1))).scalars())
        next_cursor = None
        if len(records) > limit:
            records = records[:limit]
            next_cursor = encode_score_cursor(float(records[-1].risk_score), records[-1].id)
        return [m.finding_to_domain(r) for r in records], next_cursor

    async def list_expired_acceptances(self, now: datetime) -> list[Finding]:
        stmt = self._scoped().where(
            FindingRecord.status == "ACCEPTED_RISK",
            FindingRecord.accepted_until.is_not(None),
            FindingRecord.accepted_until <= now,
        )
        return [m.finding_to_domain(r) for r in (await self._session.execute(stmt)).scalars()]

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
    ) -> dict[str, Any]:
        record = FindingCommentRecord(
            id=uuid4(),
            organization_id=organization_id,
            finding_id=finding_id,
            author_id=author_id,
            author_label=author_label[:200],
            body=body[:4000],
            status_from=status_from,
            status_to=status_to,
        )
        self._session.add(record)
        await self._session.flush()
        return _comment_to_dict(record)

    async def list_comments(self, finding_id: UUID) -> list[dict[str, Any]]:
        stmt = (
            select(FindingCommentRecord)
            .where(
                FindingCommentRecord.finding_id == finding_id,
                FindingCommentRecord.organization_id == self._organization_id,
            )
            .order_by(FindingCommentRecord.created_at)
        )
        return [_comment_to_dict(r) for r in (await self._session.execute(stmt)).scalars()]


def _comment_to_dict(record: FindingCommentRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "author_id": record.author_id,
        "author_label": record.author_label,
        "body": record.body,
        "status_from": record.status_from,
        "status_to": record.status_to,
        "created_at": record.created_at,
    }


class SqlRuleSettingsRepository(_TenantRepository):
    """One row per tenant, holding which rules they have switched off."""

    async def get(self) -> TenantRuleSettings:
        """Never returns None.

        A tenant who has never touched their settings has every rule on, and representing that
        as an absent row would make every caller handle a null that means "the default". The
        row is created lazily on the first change instead.
        """
        record = (
            await self._session.execute(
                select(TenantRuleSettingsRecord).where(
                    TenantRuleSettingsRecord.organization_id == self._organization_id
                )
            )
        ).scalar_one_or_none()
        if record is None:
            return TenantRuleSettings(organization_id=self._organization_id)
        return m.rule_settings_to_domain(record)

    async def save(self, settings: TenantRuleSettings) -> TenantRuleSettings:
        record = (
            await self._session.execute(
                select(TenantRuleSettingsRecord).where(
                    TenantRuleSettingsRecord.organization_id == self._organization_id
                )
            )
        ).scalar_one_or_none()
        if record is None:
            record = m.rule_settings_to_record(settings)
            self._session.add(record)
        else:
            record.disabled = dict(settings.disabled)
        await self._session.flush()
        return m.rule_settings_to_domain(record)
