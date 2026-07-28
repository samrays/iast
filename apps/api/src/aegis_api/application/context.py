"""The authenticated principal and the ambient request context.

Every use case takes a :class:`Principal`. There is no "current user" global and no way to
call a use case without stating who is calling — which is what makes the authorization
story auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from ..domain.entities import ActorType, Membership
from ..domain.errors import PermissionDeniedError
from ..domain.permissions import Permission


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Ambient facts about the call, recorded on audit entries and sessions.

    None of these are used for authorization. IP-based trust is a footgun: proxies rewrite
    it, attackers spoof it, and legitimate users roam.
    """

    request_id: str = ""
    ip_address: str | None = None
    user_agent: str = ""

    @classmethod
    def empty(cls) -> RequestContext:
        return cls()


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller, already resolved to a tenant and a permission set.

    Permissions are resolved from the database on every request rather than trusted from
    the access token's ``perms`` claim, so revoking a role takes effect immediately
    (ADR-0006).
    """

    kind: ActorType
    organization_id: UUID
    permissions: frozenset[Permission] = frozenset()
    user_id: UUID | None = None
    session_id: UUID | None = None
    api_key_id: UUID | None = None
    agent_id: UUID | None = None
    membership_id: UUID | None = None
    label: str = ""
    mfa_satisfied: bool = False
    is_platform_admin: bool = False
    is_owner: bool = False
    context: RequestContext = field(default_factory=RequestContext.empty)

    # --- construction --------------------------------------------------------

    @classmethod
    def for_membership(
        cls,
        membership: Membership,
        *,
        session_id: UUID | None,
        label: str,
        mfa_satisfied: bool,
        is_platform_admin: bool = False,
        context: RequestContext | None = None,
    ) -> Principal:
        return cls(
            kind=ActorType.USER,
            organization_id=membership.organization_id,
            permissions=membership.permissions,
            user_id=membership.user_id,
            session_id=session_id,
            membership_id=membership.id,
            label=label,
            mfa_satisfied=mfa_satisfied,
            is_platform_admin=is_platform_admin,
            is_owner=membership.is_owner,
            context=context or RequestContext.empty(),
        )

    @classmethod
    def system(cls, organization_id: UUID, *, label: str = "system") -> Principal:
        """A principal for background jobs and bootstrap operations.

        It holds every permission, which is precisely why it is only ever constructed in
        the CLI and in scheduled jobs — never from anything a request can reach.
        """
        return cls(
            kind=ActorType.SYSTEM,
            organization_id=organization_id,
            permissions=frozenset(Permission),
            label=label,
            mfa_satisfied=True,
        )

    def with_context(self, context: RequestContext) -> Principal:
        return Principal(
            kind=self.kind,
            organization_id=self.organization_id,
            permissions=self.permissions,
            user_id=self.user_id,
            session_id=self.session_id,
            api_key_id=self.api_key_id,
            agent_id=self.agent_id,
            membership_id=self.membership_id,
            label=self.label,
            mfa_satisfied=self.mfa_satisfied,
            is_platform_admin=self.is_platform_admin,
            is_owner=self.is_owner,
            context=context,
        )

    # --- authorization -------------------------------------------------------

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        """Raise unless this principal holds ``permission``.

        This is *the* authorization primitive. Use cases call it directly; the HTTP layer's
        equivalent dependency exists only to fail fast before the transaction opens.
        """
        if permission not in self.permissions:
            raise PermissionDeniedError(permission.value)

    def require_any(self, *permissions: Permission) -> None:
        if not any(p in self.permissions for p in permissions):
            raise PermissionDeniedError(" or ".join(p.value for p in permissions))

    def assert_can_grant(self, permissions: frozenset[Permission]) -> None:
        """Reject an attempt to grant permissions this principal does not hold (T-10)."""
        from ..domain.errors import PrivilegeEscalationError

        missing = frozenset(permissions) - self.permissions
        if missing:
            raise PrivilegeEscalationError([p.value for p in missing])

    @property
    def is_user(self) -> bool:
        return self.kind is ActorType.USER

    @property
    def audit_actor_id(self) -> UUID | None:
        return self.user_id
