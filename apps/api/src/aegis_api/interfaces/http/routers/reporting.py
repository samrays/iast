"""Compliance reporting routes: PCI DSS 4.0, SOC 2, ISO 27001, NIST 800-53, OWASP ASVS."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse

from ....application.reporting import GenerateComplianceReport
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, requires

router = APIRouter(
    prefix="/compliance",
    tags=["compliance"],
    dependencies=[Depends(requires(Permission.FINDING_READ))],
)


@router.get(
    "/report",
    summary="Generate compliance mapping and attestation report",
)
async def generate_compliance_report(
    principal: PrincipalDep,
    container: ContainerDep,
    framework: Annotated[str, Query(pattern="^(pci_dss|soc_2|iso_27001|nist_800_53|owasp_asvs)$")] = "pci_dss",
    fmt: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
    application_id: UUID | None = None,
) -> Response:
    payload, media_type = await GenerateComplianceReport(
        uow_factory=container.unit_of_work,
        clock=container.auth.clock,
    ).execute(
        principal=principal,
        framework=framework,
        application_id=application_id,
        fmt=fmt,
    )

    if fmt == "csv" and isinstance(payload, str):
        return Response(
            content=payload,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="aegis-compliance-{framework}.csv"'},
        )

    return JSONResponse(content=payload)
