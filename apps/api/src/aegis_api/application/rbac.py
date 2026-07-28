"""Organization, membership and role management.

Every operation re-checks its permission on the principal and, for anything that grants
access, additionally verifies the caller is not escalating its own privileges (threat T-10).
"""

from __future__ import annotations

from uuid import UUID

from ..domain.entities import (
    AuditOutcome,
    Membership,
    MembershipStatus,
    Organization,
    Role,
    User,
    UserStatus,
)
from ..domain.entities.audit import AuditAction
from ..domain.errors import ConflictError, InvalidStateError, NotFoundError, ValidationError
from ..domain.permissions import Permission, parse_permission
from ..domain.ports import Clock, UnitOfWork
from ..domain.value_objects import EmailAddress
from .audit_recorder import AuditRecorder
from .context import Principal
from .dto import MemberSummary, OrganizationSummary, Page, RoleSummary


def _role_summary(role: Role) -> RoleSummary:
    return RoleSummary(
        id=role.id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=sorted(p.value for p in role.permissions),
    )


def _member_summary(membership: Membership, user: User) -> MemberSummary:
    return MemberSummary(
        membership_id=membership.id,
        user_id=user.id,
        email=user.email.value,
        full_name=user.full_name,
        status=membership.status.value,
        roles=[_role_summary(r) for r in membership.roles],
        permissions=sorted(p.value for p in membership.permissions),
        joined_at=membership.joined_at,
        last_login_at=user.last_login_at,
    )


def parse_permissions(raw: list[str]) -> frozenset[Permission]:
    """Parse submitted permission strings, rejecting unknown values.

    Ignoring a typo would silently create a role weaker than the administrator believes.
    """
    unknown: list[str] = []
    parsed: set[Permission] = set()
    for item in raw:
        try:
            parsed.add(parse_permission(item))
        except ValueError:
            unknown.append(item)
    if unknown:
        raise ValidationError(
            "Unknown permissions: " + ", ".join(sorted(unknown)), field="permissions"
        )
    return frozenset(parsed)


# --- Organization ---------------------------------------------------------------------


class GetOrganization:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal) -> OrganizationSummary:
        principal.require(Permission.ORG_READ)
        async with self._uow as uow:
            organization = await uow.organizations.get(principal.organization_id)
            if organization is None:  # pragma: no cover - defensive
                raise NotFoundError("Organization", principal.organization_id)
            return OrganizationSummary(
                id=organization.id,
                name=organization.name,
                slug=organization.slug.value,
                status=organization.status.value,
            )


class UpdateOrganization:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, name: str | None, settings: dict[str, object] | None
    ) -> OrganizationSummary:
        principal.require(Permission.ORG_WRITE)
        async with self._uow as uow:
            organization = await uow.organizations.get(principal.organization_id)
            if organization is None:  # pragma: no cover - defensive
                raise NotFoundError("Organization", principal.organization_id)

            changed: dict[str, object] = {}
            if name is not None:
                organization.rename(name)
                changed["name"] = organization.name
            if settings is not None:
                organization.settings = {**organization.settings, **settings}
                changed["settings_keys"] = sorted(settings)

            await uow.organizations.update(organization)
            await uow.bind_tenant(principal.organization_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.ORGANIZATION_UPDATED.value,
                resource_type="organization",
                resource_id=organization.id,
                metadata=changed,
            )
            await uow.commit()
            return OrganizationSummary(
                id=organization.id,
                name=organization.name,
                slug=organization.slug.value,
                status=organization.status.value,
            )


# --- Members --------------------------------------------------------------------------


class ListMembers:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, limit: int, cursor: str | None
    ) -> Page[MemberSummary]:
        principal.require(Permission.ORG_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            memberships, next_cursor = await uow.memberships.list_all(limit=limit, cursor=cursor)
            summaries: list[MemberSummary] = []
            for membership in memberships:
                user = await uow.users.get(membership.user_id)
                if user is not None:
                    summaries.append(_member_summary(membership, user))
            return Page(items=summaries, next_cursor=next_cursor, limit=limit)


class InviteMember:
    """Add a user to the organization, creating the account if it does not exist.

    An invited user has no password; they set one through the invitation flow. We do not
    reveal whether the address already had an account — the response is identical either
    way, because membership lists are sensitive.
    """

    def __init__(self, uow: UnitOfWork, clock: Clock) -> None:
        self._uow = uow
        self._clock = clock

    async def execute(
        self, *, principal: Principal, email: str, full_name: str, role_ids: list[UUID]
    ) -> MemberSummary:
        principal.require(Permission.USER_INVITE)
        address = EmailAddress(email)

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)

            roles = await self._resolve_roles(uow, principal, role_ids)
            license_ = await uow.licenses.get_for_organization(principal.organization_id)
            if license_ is not None:
                license_.check_users(await uow.memberships.count())

            user = await uow.users.get_by_email(address)
            if user is None:
                user = User(email=address, full_name=full_name, status=UserStatus.INVITED)
                await uow.users.add(user)

            existing = await uow.memberships.get_for_user(user.id)
            if existing is not None:
                raise ConflictError("This person is already a member of the organization.")

            membership = Membership(
                organization_id=principal.organization_id,
                user_id=user.id,
                roles=roles,
                status=MembershipStatus.INVITED,
                invited_by=principal.user_id,
            )
            await uow.memberships.add(membership)

            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.MEMBER_INVITED.value,
                resource_type="membership",
                resource_id=membership.id,
                metadata={
                    "email": address.value,
                    "roles": sorted(r.name for r in roles),
                },
            )
            await uow.commit()
            return _member_summary(membership, user)

    @staticmethod
    async def _resolve_roles(
        uow: UnitOfWork, principal: Principal, role_ids: list[UUID]
    ) -> tuple[Role, ...]:
        if not role_ids:
            raise ValidationError("At least one role must be assigned.", field="role_ids")
        roles = await uow.roles.get_many(role_ids)
        if len(roles) != len(set(role_ids)):
            raise NotFoundError("Role", role_ids)
        granted: set[Permission] = set()
        for role in roles:
            granted |= role.permissions
        principal.assert_can_grant(frozenset(granted))
        return tuple(roles)


class UpdateMemberRoles:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, membership_id: UUID, role_ids: list[UUID]
    ) -> MemberSummary:
        principal.require(Permission.ROLE_WRITE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            membership = await uow.memberships.get(membership_id)
            if membership is None:
                raise NotFoundError("Membership", membership_id)

            roles = await InviteMember._resolve_roles(uow, principal, role_ids)

            was_owner = membership.is_owner
            membership.assign_roles(roles)
            if was_owner and not membership.is_owner and await uow.memberships.count_owners() <= 1:
                raise InvalidStateError("An organization must retain at least one Owner.")

            await uow.memberships.update(membership)
            user = await uow.users.get(membership.user_id)
            if user is None:  # pragma: no cover - referential integrity guarantees this
                raise NotFoundError("User", membership.user_id)

            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.MEMBER_ROLES_CHANGED.value,
                resource_type="membership",
                resource_id=membership.id,
                metadata={"roles": sorted(r.name for r in roles), "user_id": str(user.id)},
            )
            await uow.commit()
            return _member_summary(membership, user)


class RemoveMember:
    def __init__(self, uow: UnitOfWork, clock: Clock) -> None:
        self._uow = uow
        self._clock = clock

    async def execute(self, *, principal: Principal, membership_id: UUID) -> None:
        principal.require(Permission.USER_REMOVE)
        now = self._clock.now()

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            membership = await uow.memberships.get(membership_id)
            if membership is None:
                raise NotFoundError("Membership", membership_id)
            if membership.user_id == principal.user_id:
                raise InvalidStateError("You cannot remove your own membership.")
            if membership.is_owner and await uow.memberships.count_owners() <= 1:
                raise InvalidStateError("An organization must retain at least one Owner.")

            await uow.memberships.delete(membership_id)
            # Removing access must also end any live session in this organization.
            await uow.sessions.revoke_all_for_user(
                membership.user_id, now=now, reason="membership_removed"
            )
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.MEMBER_REMOVED.value,
                resource_type="membership",
                resource_id=membership_id,
                metadata={"user_id": str(membership.user_id)},
            )
            await uow.commit()


# --- Roles ----------------------------------------------------------------------------


class ListRoles:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal) -> list[RoleSummary]:
        principal.require(Permission.ORG_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            return [_role_summary(r) for r in await uow.roles.list_all()]


class CreateRole:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, name: str, description: str, permissions: list[str]
    ) -> RoleSummary:
        principal.require(Permission.ROLE_WRITE)
        parsed = parse_permissions(permissions)
        principal.assert_can_grant(parsed)

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            if await uow.roles.get_by_name(name.strip()) is not None:
                raise ConflictError(f"A role named {name.strip()!r} already exists.")

            role = Role(
                organization_id=principal.organization_id,
                name=name,
                description=description,
                permissions=frozenset(),
            )
            # Route the permission set through ``update`` so the owner-only guard applies
            # to creation exactly as it does to editing.
            role.update(permissions=parsed)
            await uow.roles.add(role)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.ROLE_CREATED.value,
                resource_type="role",
                resource_id=role.id,
                metadata={"name": role.name, "permissions": sorted(p.value for p in parsed)},
            )
            await uow.commit()
            return _role_summary(role)


class UpdateRole:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        role_id: UUID,
        name: str | None,
        description: str | None,
        permissions: list[str] | None,
    ) -> RoleSummary:
        principal.require(Permission.ROLE_WRITE)
        parsed = parse_permissions(permissions) if permissions is not None else None
        if parsed is not None:
            principal.assert_can_grant(parsed)

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            role = await uow.roles.get(role_id)
            if role is None:
                raise NotFoundError("Role", role_id)

            if name is not None and name.strip() != role.name:
                clash = await uow.roles.get_by_name(name.strip())
                if clash is not None:
                    raise ConflictError(f"A role named {name.strip()!r} already exists.")

            role.update(name=name, description=description, permissions=parsed)
            await uow.roles.update(role)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.ROLE_UPDATED.value,
                resource_type="role",
                resource_id=role.id,
                metadata={"permissions": sorted(p.value for p in role.permissions)},
            )
            await uow.commit()
            return _role_summary(role)


class DeleteRole:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal, role_id: UUID) -> None:
        principal.require(Permission.ROLE_WRITE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            role = await uow.roles.get(role_id)
            if role is None:
                raise NotFoundError("Role", role_id)
            role.assert_mutable()

            in_use = await uow.roles.count_memberships_using(role_id)
            if in_use:
                raise ConflictError(
                    f"This role is assigned to {in_use} member(s). "
                    "Reassign them before deleting it."
                )

            await uow.roles.delete(role_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.ROLE_DELETED.value,
                resource_type="role",
                resource_id=role_id,
                metadata={"name": role.name},
            )
            await uow.commit()


class RecordDeniedAction:
    """Write a ``DENIED`` audit entry when authorization fails.

    Denials are the entries a security team actually reads, so they are recorded even
    though the operation itself did nothing.
    """

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, action: str, resource_type: str, detail: str
    ) -> None:
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=action,
                resource_type=resource_type,
                outcome=AuditOutcome.DENIED,
                metadata={"detail": detail},
            )
            await uow.commit()


def summarize_organization(organization: Organization) -> OrganizationSummary:
    return OrganizationSummary(
        id=organization.id,
        name=organization.name,
        slug=organization.slug.value,
        status=organization.status.value,
    )
