"""Finding routes: the queue, the evidence, and the triage decisions."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse

from ....application.findings import (
    CommentOnFinding,
    GetFinding,
    ListFindings,
    TriageFinding,
)
from ....application.sarif import ExportFindingsAsSarif
from ....domain.entities.findings import FindingStatus
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, SettingsDep, requires
from ..schemas import (
    FindingCommentRequest,
    FindingCommentResponse,
    FindingDetailResponse,
    FindingResponse,
    PageResponse,
    TriageRequest,
)

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
    # Reading is the floor. Triage and suppression are checked per-route, because they are
    # materially different acts: one moves a defect through a workflow, the other takes a
    # live vulnerability out of everyone's queue.
    dependencies=[Depends(requires(Permission.FINDING_READ))],
)


@router.get("", response_model=PageResponse[FindingResponse], summary="Browse findings")
async def list_findings(
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    rule_key: Annotated[str | None, Query(max_length=60)] = None,
    application_id: UUID | None = None,
    environment: Annotated[str | None, Query(max_length=20)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> PageResponse[FindingResponse]:
    page = await ListFindings(container.unit_of_work()).execute(
        principal=principal,
        limit=min(limit, settings.max_page_size),
        cursor=cursor,
        status=status_filter,
        severity=severity,
        rule_key=rule_key,
        application_id=application_id,
        environment=environment,
        search=search,
    )
    return PageResponse.of(page, [FindingResponse.of(item) for item in page.items])


@router.get(
    "/export/sarif",
    summary="Export findings as SARIF 2.1.0 for code scanning",
    response_model=None,
)
async def export_sarif(
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
    application_id: UUID | None = None,
) -> JSONResponse:
    """SARIF, so findings arrive in a pull request rather than waiting in a console.

    Declared before ``/{finding_id}`` deliberately: FastAPI matches in declaration order, and
    the other way round ``export`` would be parsed as a finding id and 422 on every call.
    """
    document = await ExportFindingsAsSarif(container.unit_of_work()).execute(
        principal=principal,
        application_id=application_id,
        tool_version=settings.version,
    )
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": 'attachment; filename="aegis-findings.sarif"'},
    )


@router.get(
    "/{finding_id}",
    response_model=FindingDetailResponse,
    summary="One finding, with evidence and triage history",
)
async def get_finding(
    finding_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> FindingDetailResponse:
    finding, occurrences, comments = await GetFinding(container.unit_of_work()).execute(
        principal=principal, finding_id=finding_id
    )
    return FindingDetailResponse.of(finding, occurrences, comments)


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Move a finding through its lifecycle",
)
async def triage_finding(
    finding_id: UUID,
    payload: TriageRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> FindingResponse:
    finding = await TriageFinding(container.unit_of_work()).execute(
        principal=principal,
        finding_id=finding_id,
        status=FindingStatus(payload.status),
        note=payload.note,
        accepted_for_days=payload.accepted_for_days,
    )
    return FindingResponse.of(finding)


@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add to the triage thread",
)
async def comment_on_finding(
    finding_id: UUID,
    payload: FindingCommentRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> FindingCommentResponse:
    comment = await CommentOnFinding(container.unit_of_work()).execute(
        principal=principal, finding_id=finding_id, body=payload.body
    )
    return FindingCommentResponse(**comment)
