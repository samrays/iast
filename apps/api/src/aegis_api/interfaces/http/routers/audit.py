"""Audit log routes."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from ....application.audit import ListAuditEvents, VerifyAuditChain
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, SettingsDep, requires
from ..schemas import AuditEventResponse, ChainVerificationResponse, PageResponse

router = APIRouter(
    prefix="/audit-events",
    tags=["audit"],
    dependencies=[Depends(requires(Permission.AUDIT_READ))],
)


@router.get("", response_model=PageResponse[AuditEventResponse], summary="Browse the audit log")
async def list_audit_events(
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    actor_user_id: UUID | None = None,
    occurred_after: datetime | None = None,
) -> PageResponse[AuditEventResponse]:
    page = await ListAuditEvents(container.unit_of_work()).execute(
        principal=principal,
        limit=min(limit, settings.max_page_size),
        cursor=cursor,
        action=action,
        actor_user_id=actor_user_id,
        occurred_after=occurred_after,
    )
    return PageResponse.of(page, [AuditEventResponse.of(item) for item in page.items])


@router.get(
    "/verify",
    response_model=ChainVerificationResponse,
    summary="Verify the tamper-evident hash chain",
)
async def verify_chain(
    principal: PrincipalDep,
    container: ContainerDep,
    limit: Annotated[int | None, Query(ge=1, le=100_000)] = None,
) -> ChainVerificationResponse:
    result = await VerifyAuditChain(container.unit_of_work()).execute(
        principal=principal, limit=limit
    )
    return ChainVerificationResponse(
        intact=result.intact,
        entries_checked=result.entries_checked,
        first_broken_sequence=result.first_broken_sequence,
    )
