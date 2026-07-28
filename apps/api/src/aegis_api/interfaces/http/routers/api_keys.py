"""API key routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status

from ....application.api_keys import CreateApiKey, ListApiKeys, RevokeApiKey
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, requires
from ..schemas import ApiKeyIssuedResponse, ApiKeyResponse, CreateApiKeyRequest

router = APIRouter(
    prefix="/api-keys",
    tags=["api-keys"],
    dependencies=[Depends(requires(Permission.SETTINGS_WRITE))],
)


@router.get("", response_model=list[ApiKeyResponse], summary="List API keys")
async def list_api_keys(principal: PrincipalDep, container: ContainerDep) -> list[ApiKeyResponse]:
    keys = await ListApiKeys(container.unit_of_work()).execute(principal=principal)
    return [ApiKeyResponse.of(k) for k in keys]


@router.post(
    "",
    response_model=ApiKeyIssuedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue an API key — the secret is returned exactly once",
)
async def create_api_key(
    payload: CreateApiKeyRequest, principal: PrincipalDep, container: ContainerDep
) -> ApiKeyIssuedResponse:
    issued = await CreateApiKey(
        container.unit_of_work(), container.auth.clock, container.auth.hasher
    ).execute(
        principal=principal,
        name=payload.name,
        permissions=payload.permissions,
        expires_in_days=payload.expires_in_days,
    )
    return ApiKeyIssuedResponse(
        api_key=ApiKeyResponse.of(issued.summary), secret=issued.plaintext_key
    )


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke an API key")
async def revoke_api_key(
    api_key_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> None:
    await RevokeApiKey(container.unit_of_work(), container.auth.clock).execute(
        principal=principal, api_key_id=api_key_id
    )
