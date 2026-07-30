"""The SQLAlchemy unit of work.

One use case, one transaction, one tenant binding. The tenant-scoped repositories are only
reachable after :meth:`bind_tenant`, so a query that would cross tenants cannot be written
by accident — it fails loudly at construction instead of returning the wrong rows.
"""

from __future__ import annotations

from types import TracebackType
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...domain.entities import Organization
from ...domain.errors import DomainError
from . import mappers as m
from .models import MembershipRecord, OrganizationRecord
from .repositories import (
    SqlAgentRepository,
    SqlApiKeyLookup,
    SqlApiKeyRepository,
    SqlApplicationRepository,
    SqlAuditRepository,
    SqlEnvironmentRepository,
    SqlFindingRepository,
    SqlLicenseRepository,
    SqlMembershipRepository,
    SqlMfaCredentialRepository,
    SqlOrganizationRepository,
    SqlRoleRepository,
    SqlRuleSettingsRepository,
    SqlSessionRepository,
    SqlUserRepository,
)


class TenantNotBoundError(DomainError):
    """Raised when tenant-scoped data is touched before a tenant is established."""

    code = "tenant_not_bound"
    message = "This operation requires a tenant context."


class SqlUnitOfWork:
    """Transaction boundary backed by one ``AsyncSession``.

    Entering the context opens a transaction; leaving it rolls back unless :meth:`commit`
    was called. That default matters: a use case that raises halfway through never leaves
    a partial write behind.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None
        self._organization_id: UUID | None = None
        self._committed = False

    # --- context management ---------------------------------------------------

    async def __aenter__(self) -> SqlUnitOfWork:
        if self._session is not None:
            # Re-entering an open unit of work is a bug: it would silently nest and the
            # inner commit would publish the outer's partial state.
            raise RuntimeError("This unit of work is already open.")
        self._session = self._session_factory()
        self._committed = False
        self._organization_id = None

        self._organizations = SqlOrganizationRepository(self._session)
        self._licenses = SqlLicenseRepository(self._session)
        self._users = SqlUserRepository(self._session)
        self._mfa_credentials = SqlMfaCredentialRepository(self._session)
        self._sessions = SqlSessionRepository(self._session)
        self._api_key_lookup = SqlApiKeyLookup(self._session)
        return self

    # --- global repositories --------------------------------------------------

    @property
    def organizations(self) -> SqlOrganizationRepository:
        return self._organizations

    @property
    def licenses(self) -> SqlLicenseRepository:
        return self._licenses

    @property
    def users(self) -> SqlUserRepository:
        return self._users

    @property
    def mfa_credentials(self) -> SqlMfaCredentialRepository:
        return self._mfa_credentials

    @property
    def sessions(self) -> SqlSessionRepository:
        return self._sessions

    @property
    def api_key_lookup(self) -> SqlApiKeyLookup:
        return self._api_key_lookup

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        session = self._session
        self._session = None
        if session is None:  # pragma: no cover - defensive
            return
        try:
            if exc_type is not None or not self._committed:
                await session.rollback()
        finally:
            await session.close()

    # --- transaction ----------------------------------------------------------

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            raise RuntimeError("This unit of work is not open.")
        return self._session

    async def commit(self) -> None:
        await self.session.commit()
        self._committed = True

    async def rollback(self) -> None:
        await self.session.rollback()
        self._committed = False

    # --- tenant binding -------------------------------------------------------

    async def bind_tenant(self, organization_id: UUID) -> None:
        """Scope this transaction to a tenant.

        Sets the ``app.current_organization_id`` GUC that the row-level-security policies
        read, and constructs the tenant-scoped repositories. ``set_config(..., true)``
        makes the setting transaction-local, which is essential behind a connection pool:
        a session-level setting would leak into the next request that reused the
        connection.
        """
        await self.session.execute(
            text("SELECT set_config('app.current_organization_id', :org_id, true)"),
            {"org_id": str(organization_id)},
        )
        self._organization_id = organization_id
        self._memberships = SqlMembershipRepository(self.session, organization_id)
        self._roles = SqlRoleRepository(self.session, organization_id)
        self._api_keys = SqlApiKeyRepository(self.session, organization_id)
        self._applications = SqlApplicationRepository(self.session, organization_id)
        self._environments = SqlEnvironmentRepository(self.session, organization_id)
        self._agents = SqlAgentRepository(self.session, organization_id)
        self._audit = SqlAuditRepository(self.session, organization_id)
        self._findings = SqlFindingRepository(self.session, organization_id)
        self._rule_settings = SqlRuleSettingsRepository(self.session, organization_id)

    @property
    def bound_organization_id(self) -> UUID | None:
        return self._organization_id

    def _require_tenant(self) -> None:
        if self._organization_id is None:
            raise TenantNotBoundError("Call bind_tenant() before using tenant-scoped repositories.")

    @property
    def memberships(self) -> SqlMembershipRepository:
        self._require_tenant()
        return self._memberships

    @property
    def roles(self) -> SqlRoleRepository:
        self._require_tenant()
        return self._roles

    @property
    def api_keys(self) -> SqlApiKeyRepository:
        self._require_tenant()
        return self._api_keys

    @property
    def applications(self) -> SqlApplicationRepository:
        self._require_tenant()
        return self._applications

    @property
    def environments(self) -> SqlEnvironmentRepository:
        self._require_tenant()
        return self._environments

    @property
    def agents(self) -> SqlAgentRepository:
        self._require_tenant()
        return self._agents

    @property
    def audit(self) -> SqlAuditRepository:
        self._require_tenant()
        return self._audit

    @property
    def findings(self) -> SqlFindingRepository:
        self._require_tenant()
        return self._findings

    @property
    def rule_settings(self) -> SqlRuleSettingsRepository:
        self._require_tenant()
        return self._rule_settings

    # --- cross-tenant, by necessity -------------------------------------------

    async def find_active_organizations_for_user(self, user_id: UUID) -> list[Organization]:
        """Which tenants may this person sign in to.

        The one query that legitimately spans tenants. It joins ``memberships``, which is
        RLS-protected, at a point where no tenant is yet bound — so it temporarily raises
        the ``app.rls_bypass`` flag the policy recognizes, and lowers it immediately
        afterwards. Both settings are transaction-local.

        The blast radius is deliberately tiny: the flag is raised around exactly one
        statement, the statement is filtered to this user's own memberships, and it returns
        organization rows only — never tenant-owned data.
        """
        stmt = (
            select(OrganizationRecord)
            .join(MembershipRecord, MembershipRecord.organization_id == OrganizationRecord.id)
            .where(
                MembershipRecord.user_id == user_id,
                MembershipRecord.status == "ACTIVE",
                OrganizationRecord.status == "ACTIVE",
            )
            .order_by(OrganizationRecord.name)
        )
        await self.session.execute(text("SELECT set_config('app.rls_bypass', 'on', true)"))
        try:
            records = (await self.session.execute(stmt)).scalars().all()
        finally:
            await self.session.execute(text("SELECT set_config('app.rls_bypass', 'off', true)"))
        return [m.organization_to_domain(r) for r in records]
