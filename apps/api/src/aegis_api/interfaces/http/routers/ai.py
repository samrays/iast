"""AI Analysis routes: Root Cause Analysis, Remediation generation, and Human Review."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status

from ....application.ai import AnalyseFinding, EchoModel, ReviewAnalysis
from ....domain.entities.ai import AnalysisKind
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, requires
from ..schemas import AiAnalysisResponse, AnalyzeFindingRequest, ReviewAnalysisRequest

router = APIRouter(
    prefix="",
    tags=["ai-analysis"],
    dependencies=[Depends(requires(Permission.FINDING_READ))],
)


@router.post(
    "/findings/{finding_id}/analyze",
    response_model=AiAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger AI Root Cause or Remediation analysis for a finding",
)
async def analyze_finding(
    finding_id: UUID,
    payload: AnalyzeFindingRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> AiAnalysisResponse:
    model = EchoModel()
    analysis = await AnalyseFinding(
        uow_factory=container.unit_of_work,
        model=model,
        clock=container.auth.clock,
    ).execute(
        principal=principal,
        finding_id=finding_id,
        kind=AnalysisKind(payload.kind),
    )
    return AiAnalysisResponse.of(analysis)


@router.post(
    "/analyses/{analysis_id}/review",
    response_model=AiAnalysisResponse,
    summary="Accept or Reject a draft AI analysis (Human-in-the-Loop review)",
)
async def review_analysis(
    analysis_id: UUID,
    payload: ReviewAnalysisRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> AiAnalysisResponse:
    analysis = await ReviewAnalysis(
        uow_factory=container.unit_of_work,
        clock=container.auth.clock,
    ).execute(
        principal=principal,
        analysis_id=analysis_id,
        accept=payload.accept,
        note=payload.note,
    )
    return AiAnalysisResponse.of(analysis)
