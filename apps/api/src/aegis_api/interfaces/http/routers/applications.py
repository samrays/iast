"""Application inventory routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from ....application.inventory import (
    CreateApplication,
    CreateEnvironment,
    DeleteApplication,
    GetApplication,
    ListApplications,
    ListEnvironments,
    SetProtectionMode,
    UpdateApplication,
)
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, SettingsDep, requires
from ..schemas import (
    ApplicationResponse,
    CreateApplicationRequest,
    CreateEnvironmentRequest,
    EnvironmentResponse,
    PageResponse,
    SetProtectionModeRequest,
    UpdateApplicationRequest,
)

router = APIRouter(prefix="/applications", tags=["applications"])

#: Environments are addressed by their own id once created, so they get their own prefix
#: rather than being nested under an application path that would have to be re-verified.
environments_router = APIRouter(prefix="/environments", tags=["applications"])


@router.get("", response_model=PageResponse[ApplicationResponse], summary="List applications")
async def list_applications(
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
    q: Annotated[str | None, Query(max_length=120)] = None,
    tag: Annotated[list[str] | None, Query()] = None,
) -> PageResponse[ApplicationResponse]:
    page = await ListApplications(container.unit_of_work()).execute(
        principal=principal,
        limit=min(limit, settings.max_page_size),
        cursor=cursor,
        search=q,
        tags=tag,
    )
    return PageResponse.of(page, [ApplicationResponse.of(item) for item in page.items])


@router.post(
    "",
    response_model=ApplicationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(requires(Permission.APP_WRITE))],
    summary="Register an application",
)
async def create_application(
    payload: CreateApplicationRequest,
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
) -> ApplicationResponse:
    result = await CreateApplication(
        container.unit_of_work(), container.auth.clock, settings.inventory_policy
    ).execute(
        principal=principal,
        name=payload.name,
        language=payload.language,
        criticality=payload.criticality,
        tags=payload.tags,
        repository_url=payload.repository_url,
        description=payload.description,
        environments=[(e.kind, e.internet_facing) for e in payload.environments] or None,
    )
    return ApplicationResponse.of(result)


@router.get("/{application_id}", response_model=ApplicationResponse, summary="Get an application")
async def get_application(
    application_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> ApplicationResponse:
    result = await GetApplication(container.unit_of_work()).execute(
        principal=principal, application_id=application_id
    )
    return ApplicationResponse.of(result)


@router.patch(
    "/{application_id}",
    response_model=ApplicationResponse,
    dependencies=[Depends(requires(Permission.APP_WRITE))],
    summary="Update an application",
)
async def update_application(
    application_id: UUID,
    payload: UpdateApplicationRequest,
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
) -> ApplicationResponse:
    result = await UpdateApplication(container.unit_of_work(), settings.inventory_policy).execute(
        principal=principal,
        application_id=application_id,
        name=payload.name,
        criticality=payload.criticality,
        tags=payload.tags,
        repository_url=payload.repository_url,
        description=payload.description,
    )
    return ApplicationResponse.of(result)


@router.delete(
    "/{application_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(requires(Permission.APP_DELETE))],
    summary="Delete an application and everything attached to it",
)
async def delete_application(
    application_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> None:
    await DeleteApplication(container.unit_of_work()).execute(
        principal=principal, application_id=application_id
    )


@router.get(
    "/{application_id}/environments",
    response_model=list[EnvironmentResponse],
    summary="List environments",
)
async def list_environments(
    application_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> list[EnvironmentResponse]:
    items = await ListEnvironments(container.unit_of_work()).execute(
        principal=principal, application_id=application_id
    )
    return [EnvironmentResponse.of(e) for e in items]


@router.post(
    "/{application_id}/environments",
    response_model=EnvironmentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(requires(Permission.APP_WRITE))],
    summary="Add an environment",
)
async def create_environment(
    application_id: UUID,
    payload: CreateEnvironmentRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> EnvironmentResponse:
    result = await CreateEnvironment(container.unit_of_work()).execute(
        principal=principal,
        application_id=application_id,
        kind=payload.kind,
        internet_facing=payload.internet_facing,
    )
    return EnvironmentResponse.of(result)


@environments_router.put(
    "/{environment_id}/protection",
    response_model=EnvironmentResponse,
    dependencies=[Depends(requires(Permission.POLICY_WRITE))],
    summary="Set the Application Detection & Response mode",
)
async def set_protection_mode(
    environment_id: UUID,
    payload: SetProtectionModeRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> EnvironmentResponse:
    result = await SetProtectionMode(container.unit_of_work(), container.auth.clock).execute(
        principal=principal, environment_id=environment_id, mode=payload.mode
    )
    return EnvironmentResponse.of(result)
