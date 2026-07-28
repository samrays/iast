"""Organization, member, role and permission-catalogue routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from ....application.rbac import (
    CreateRole,
    DeleteRole,
    GetOrganization,
    InviteMember,
    ListMembers,
    ListRoles,
    RemoveMember,
    UpdateMemberRoles,
    UpdateOrganization,
    UpdateRole,
)
from ....domain.permissions import PRIVILEGED_PERMISSIONS, Permission
from ..dependencies import ContainerDep, PrincipalDep, SettingsDep, requires
from ..schemas import (
    CreateRoleRequest,
    InviteMemberRequest,
    MemberResponse,
    OrganizationResponse,
    PageResponse,
    PermissionCatalogueEntry,
    RoleResponse,
    UpdateMemberRequest,
    UpdateOrganizationRequest,
    UpdateRoleRequest,
)

router = APIRouter(tags=["organization"])


@router.get(
    "/organizations/current",
    response_model=OrganizationResponse,
    summary="The caller's organization",
)
async def get_current_organization(
    principal: PrincipalDep, container: ContainerDep
) -> OrganizationResponse:
    return OrganizationResponse.of(
        await GetOrganization(container.unit_of_work()).execute(principal=principal)
    )


@router.patch(
    "/organizations/current", response_model=OrganizationResponse, summary="Update the organization"
)
async def update_current_organization(
    payload: UpdateOrganizationRequest, principal: PrincipalDep, container: ContainerDep
) -> OrganizationResponse:
    result = await UpdateOrganization(container.unit_of_work()).execute(
        principal=principal, name=payload.name, settings=payload.settings
    )
    return OrganizationResponse.of(result)


@router.get(
    "/organizations/current/members",
    response_model=PageResponse[MemberResponse],
    summary="List members",
)
async def list_members(
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
) -> PageResponse[MemberResponse]:
    page = await ListMembers(container.unit_of_work()).execute(
        principal=principal, limit=min(limit, settings.max_page_size), cursor=cursor
    )
    return PageResponse.of(page, [MemberResponse.of(item) for item in page.items])


@router.post(
    "/organizations/current/members/invite",
    response_model=MemberResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(requires(Permission.USER_INVITE))],
    summary="Invite a member",
)
async def invite_member(
    payload: InviteMemberRequest, principal: PrincipalDep, container: ContainerDep
) -> MemberResponse:
    result = await InviteMember(container.unit_of_work(), container.auth.clock).execute(
        principal=principal,
        email=payload.email,
        full_name=payload.full_name,
        role_ids=payload.role_ids,
    )
    return MemberResponse.of(result)


@router.patch(
    "/organizations/current/members/{membership_id}",
    response_model=MemberResponse,
    dependencies=[Depends(requires(Permission.ROLE_WRITE))],
    summary="Change a member's roles",
)
async def update_member(
    membership_id: UUID,
    payload: UpdateMemberRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> MemberResponse:
    result = await UpdateMemberRoles(container.unit_of_work()).execute(
        principal=principal, membership_id=membership_id, role_ids=payload.role_ids
    )
    return MemberResponse.of(result)


@router.delete(
    "/organizations/current/members/{membership_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(requires(Permission.USER_REMOVE))],
    summary="Remove a member",
)
async def remove_member(
    membership_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> None:
    await RemoveMember(container.unit_of_work(), container.auth.clock).execute(
        principal=principal, membership_id=membership_id
    )


@router.get("/organizations/current/roles", response_model=list[RoleResponse], summary="List roles")
async def list_roles(principal: PrincipalDep, container: ContainerDep) -> list[RoleResponse]:
    roles = await ListRoles(container.unit_of_work()).execute(principal=principal)
    return [RoleResponse.of(r) for r in roles]


@router.post(
    "/organizations/current/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(requires(Permission.ROLE_WRITE))],
    summary="Create a custom role",
)
async def create_role(
    payload: CreateRoleRequest, principal: PrincipalDep, container: ContainerDep
) -> RoleResponse:
    result = await CreateRole(container.unit_of_work()).execute(
        principal=principal,
        name=payload.name,
        description=payload.description,
        permissions=payload.permissions,
    )
    return RoleResponse.of(result)


@router.patch(
    "/organizations/current/roles/{role_id}",
    response_model=RoleResponse,
    dependencies=[Depends(requires(Permission.ROLE_WRITE))],
    summary="Update a custom role",
)
async def update_role(
    role_id: UUID, payload: UpdateRoleRequest, principal: PrincipalDep, container: ContainerDep
) -> RoleResponse:
    result = await UpdateRole(container.unit_of_work()).execute(
        principal=principal,
        role_id=role_id,
        name=payload.name,
        description=payload.description,
        permissions=payload.permissions,
    )
    return RoleResponse.of(result)


@router.delete(
    "/organizations/current/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(requires(Permission.ROLE_WRITE))],
    summary="Delete a custom role",
)
async def delete_role(role_id: UUID, principal: PrincipalDep, container: ContainerDep) -> None:
    await DeleteRole(container.unit_of_work()).execute(principal=principal, role_id=role_id)


@router.get(
    "/permissions",
    response_model=list[PermissionCatalogueEntry],
    summary="The assignable permission catalogue",
)
async def list_permissions(principal: PrincipalDep) -> list[PermissionCatalogueEntry]:
    """Drives the role editor. Authenticated but unprivileged — the catalogue is not secret."""
    entries: list[PermissionCatalogueEntry] = []
    for permission in Permission:
        resource, _, action = permission.value.partition(":")
        entries.append(
            PermissionCatalogueEntry(
                value=permission.value,
                resource=resource,
                action=action,
                privileged=permission in PRIVILEGED_PERMISSIONS,
            )
        )
    return entries
