"""Access entities: Role, Membership, Session and ApiKey.

Together these answer three questions: *who is this principal*, *what may it do*, and
*is its credential still valid*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from ..errors import (
    InvalidStateError,
    PermissionDeniedError,
    PrivilegeEscalationError,
)
from ..permissions import OWNER_ONLY_PERMISSIONS, Permission, SystemRole, is_privileged
from ..value_objects import ApiKeyPrefix, TokenHash, new_id


class MembershipStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVITED = "INVITED"
    SUSPENDED = "SUSPENDED"


@dataclass(slots=True)
class Role:
    """A named bundle of permissions, scoped to one organization.

    System roles are seeded per organization and cannot be edited or deleted; customers
    build custom roles alongside them. Nothing in the codebase authorizes on a role *name* —
    only on the permissions a role carries.
    """

    organization_id: UUID
    name: str
    permissions: frozenset[Permission] = frozenset()
    description: str = ""
    is_system: bool = False
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        self.name = (self.name or "").strip()
        if not self.name:
            raise InvalidStateError("A role must have a name.")
        if len(self.name) > 80:
            raise InvalidStateError("A role name may be at most 80 characters.")
        self.permissions = frozenset(self.permissions)

    @property
    def is_privileged(self) -> bool:
        return is_privileged(self.permissions)

    def assert_mutable(self) -> None:
        if self.is_system:
            raise InvalidStateError(
                f"{self.name!r} is a system role and cannot be modified or deleted."
            )

    def update(
        self,
        *,
        name: str | None = None,
        description: str | None = None,
        permissions: frozenset[Permission] | None = None,
    ) -> None:
        self.assert_mutable()
        if name is not None:
            candidate = name.strip()
            if not candidate:
                raise InvalidStateError("A role must have a name.")
            self.name = candidate[:80]
        if description is not None:
            self.description = description.strip()[:500]
        if permissions is not None:
            forbidden = frozenset(permissions) & OWNER_ONLY_PERMISSIONS
            if forbidden:
                raise InvalidStateError(
                    "These permissions belong exclusively to the Owner role: "
                    + ", ".join(sorted(p.value for p in forbidden))
                )
            self.permissions = frozenset(permissions)

    @classmethod
    def system(
        cls,
        organization_id: UUID,
        role: SystemRole,
        permissions: frozenset[Permission],
        description: str,
    ) -> Role:
        return cls(
            organization_id=organization_id,
            name=role.value,
            permissions=permissions,
            description=description,
            is_system=True,
        )


@dataclass(slots=True)
class Membership:
    """A user's participation in one organization, carrying their roles.

    This is where authorization is resolved. ``permissions`` is the union of the assigned
    roles' permissions — union, not intersection, because roles are additive grants.
    """

    organization_id: UUID
    user_id: UUID
    roles: tuple[Role, ...] = ()
    status: MembershipStatus = MembershipStatus.ACTIVE
    invited_by: UUID | None = None
    id: UUID = field(default_factory=new_id)
    joined_at: datetime | None = None
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        for role in self.roles:
            if role.organization_id != self.organization_id:
                raise InvalidStateError(
                    "A membership cannot carry a role belonging to another organization."
                )

    # --- authorization -------------------------------------------------------

    @property
    def is_active(self) -> bool:
        return self.status is MembershipStatus.ACTIVE

    @property
    def permissions(self) -> frozenset[Permission]:
        if not self.is_active:
            return frozenset()
        result: set[Permission] = set()
        for role in self.roles:
            result |= role.permissions
        return frozenset(result)

    @property
    def is_owner(self) -> bool:
        return any(role.is_system and role.name == SystemRole.OWNER.value for role in self.roles)

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.has_permission(permission):
            raise PermissionDeniedError(permission.value)

    def assert_can_grant(self, permissions: frozenset[Permission]) -> None:
        """Prevent privilege escalation (threat T-10).

        A member may only grant permissions it holds itself. Without this, anyone with
        ``role:write`` could mint a role containing every permission and assign it to
        themselves — which would make ``role:write`` equivalent to ownership.
        """
        missing = frozenset(permissions) - self.permissions
        if missing:
            raise PrivilegeEscalationError([p.value for p in missing])

    # --- role management -----------------------------------------------------

    def assign_roles(self, roles: tuple[Role, ...]) -> None:
        for role in roles:
            if role.organization_id != self.organization_id:
                raise InvalidStateError(
                    "A membership cannot carry a role belonging to another organization."
                )
        if not roles:
            raise InvalidStateError("A membership must retain at least one role.")
        self.roles = roles

    def activate(self, now: datetime) -> None:
        self.status = MembershipStatus.ACTIVE
        if self.joined_at is None:
            self.joined_at = now

    def suspend(self) -> None:
        self.status = MembershipStatus.SUSPENDED


@dataclass(slots=True)
class Session:
    """A refresh-token session (ADR-0006).

    Sessions form *families*: the session created at sign-in starts a family, and every
    rotation inherits its ``family_id``. Presenting an already-rotated token means the
    token was copied, so the whole family is revoked — killing the attacker's branch and
    the victim's alike, which is the correct outcome.
    """

    user_id: UUID
    organization_id: UUID
    family_id: UUID
    refresh_token_hash: TokenHash
    expires_at: datetime
    user_agent: str = ""
    ip_address: str | None = None
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    replaced_by_id: UUID | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None

    REUSE_REVOCATION_REASON = "token_reuse_detected"

    @classmethod
    def start(
        cls,
        *,
        user_id: UUID,
        organization_id: UUID,
        refresh_token_hash: TokenHash,
        ttl_seconds: int,
        now: datetime,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> Session:
        """Begin a new family at sign-in."""
        session_id = new_id()
        return cls(
            id=session_id,
            family_id=session_id,
            user_id=user_id,
            organization_id=organization_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=now + timedelta(seconds=ttl_seconds),
            user_agent=(user_agent or "")[:400],
            ip_address=ip_address,
            created_at=now,
        )

    def rotate(
        self,
        *,
        refresh_token_hash: TokenHash,
        now: datetime,
        absolute_expiry: datetime,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> Session:
        """Consume this session and return its successor in the same family.

        The absolute expiry is inherited, so rotation extends nothing: a family lives at
        most ``refresh_ttl_seconds`` from sign-in, no matter how often it is refreshed.
        """
        if self.revoked_at is not None:
            raise InvalidStateError("A revoked session cannot be rotated.")
        successor = Session(
            user_id=self.user_id,
            organization_id=self.organization_id,
            family_id=self.family_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=absolute_expiry,
            user_agent=(user_agent or self.user_agent)[:400],
            ip_address=ip_address or self.ip_address,
            created_at=now,
        )
        self.rotated_at = now
        self.replaced_by_id = successor.id
        return successor

    # --- state ---------------------------------------------------------------

    @property
    def is_rotated(self) -> bool:
        return self.rotated_at is not None

    def is_expired(self, now: datetime) -> bool:
        exp = self.expires_at.replace(tzinfo=UTC) if self.expires_at and self.expires_at.tzinfo is None else self.expires_at
        current = now.replace(tzinfo=UTC) if now and now.tzinfo is None else now
        if exp is None or current is None:
            return False
        return exp <= current

    def is_active(self, now: datetime) -> bool:
        return self.revoked_at is None and not self.is_rotated and not self.is_expired(now)

    def is_within_rotation_grace(self, now: datetime, grace_seconds: int) -> bool:
        """True when this session was rotated moments ago.

        Two browser tabs refreshing simultaneously both present the same token. Treating
        that as theft would sign users out constantly, so a short window accepts the
        immediate predecessor without triggering family revocation.
        """
        if self.rotated_at is None:
            return False
        rot = self.rotated_at.replace(tzinfo=UTC) if self.rotated_at.tzinfo is None else self.rotated_at
        current = now.replace(tzinfo=UTC) if now and now.tzinfo is None else now
        return (current - rot) <= timedelta(seconds=grace_seconds)

    def revoke(self, now: datetime, reason: str) -> None:
        if self.revoked_at is None:
            self.revoked_at = now
            self.revoked_reason = reason


@dataclass(slots=True)
class ApiKey:
    """A long-lived credential for CI systems and agent registration.

    Format is ``ak_<prefix>.<secret>``. The prefix is uniquely indexed and stored in the
    clear so verification is one index probe followed by one Argon2 verify; the secret is
    never stored, only its hash.
    """

    organization_id: UUID
    name: str
    prefix: ApiKeyPrefix
    secret_hash: str
    permissions: frozenset[Permission] = frozenset()
    created_by: UUID | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        self.name = (self.name or "").strip()
        if not self.name:
            raise InvalidStateError("An API key must have a name.")
        self.name = self.name[:120]
        self.permissions = frozenset(self.permissions)

    def is_active(self, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is None:
            return True
        exp = self.expires_at.replace(tzinfo=UTC) if self.expires_at.tzinfo is None else self.expires_at
        current = now.replace(tzinfo=UTC) if now and now.tzinfo is None else now
        return exp > current

    def revoke(self, now: datetime) -> None:
        if self.revoked_at is None:
            self.revoked_at = now

    def touch(self, now: datetime) -> None:
        self.last_used_at = now

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.has_permission(permission):
            raise PermissionDeniedError(permission.value)
