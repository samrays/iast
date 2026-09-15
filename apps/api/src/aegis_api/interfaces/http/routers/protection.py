"""HTTP Router for Protection Policy governance (OFF, MONITOR, BLOCK)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ....application.context import Principal
from ....application.protection import ManageProtectionPolicy
from ....domain.entities.protection import ProtectionMode
from ..dependencies import ContainerDep, PrincipalDep

router = APIRouter(prefix="/protection", tags=["protection"])


class UpdateProtectionModeRequest(BaseModel):
    mode: ProtectionMode


class ProtectionPolicyResponse(BaseModel):
    application_id: UUID
    mode: ProtectionMode
    soak_started_at: str
    would_block_count: int


def get_manage_protection(container: ContainerDep) -> ManageProtectionPolicy:
    return ManageProtectionPolicy(container.unit_of_work, container.auth.clock)


@router.get("/policies/{application_id}", response_model=ProtectionPolicyResponse)
async def get_policy(
    application_id: UUID,
    principal: PrincipalDep,
    service: Annotated[ManageProtectionPolicy, Depends(get_manage_protection)],
) -> ProtectionPolicyResponse:
    policy = await service.get_policy(principal, application_id)
    return ProtectionPolicyResponse(
        application_id=policy.application_id,
        mode=policy.mode,
        soak_started_at=policy.soak_started_at.isoformat(),
        would_block_count=policy.would_block_count,
    )


@router.put("/policies/{application_id}", response_model=ProtectionPolicyResponse)
async def update_policy(
    application_id: UUID,
    body: UpdateProtectionModeRequest,
    principal: PrincipalDep,
    service: Annotated[ManageProtectionPolicy, Depends(get_manage_protection)],
) -> ProtectionPolicyResponse:
    policy = await service.update_mode(principal, application_id, body.mode)
    return ProtectionPolicyResponse(
        application_id=policy.application_id,
        mode=policy.mode,
        soak_started_at=policy.soak_started_at.isoformat(),
        would_block_count=policy.would_block_count,
    )
