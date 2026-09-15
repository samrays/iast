"""HTTP Router for findings export (SARIF, OCSF, CEF)."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from ....application.export import ExportFindings
from ....application.context import Principal
from ..dependencies import PrincipalDep, get_export_findings

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/sarif")
async def export_sarif(
    principal: PrincipalDep,
    use_case: Annotated[ExportFindings, Depends(get_export_findings)],
    application_id: UUID | None = Query(None),
) -> dict[str, Any]:
    """Export findings in SARIF 2.1.0 JSON format for GitHub Code Scanning."""
    result, _ = await use_case.execute(
        principal=principal,
        fmt="sarif",
        application_id=application_id,
    )
    assert isinstance(result, dict)
    return result


@router.get("/ocsf")
async def export_ocsf(
    principal: PrincipalDep,
    use_case: Annotated[ExportFindings, Depends(get_export_findings)],
    application_id: UUID | None = Query(None),
) -> dict[str, Any]:
    """Export findings in OCSF Vulnerability Finding JSON format for SIEMs."""
    result, _ = await use_case.execute(
        principal=principal,
        fmt="ocsf",
        application_id=application_id,
    )
    assert isinstance(result, dict)
    return result


@router.get("/cef")
async def export_cef(
    principal: PrincipalDep,
    use_case: Annotated[ExportFindings, Depends(get_export_findings)],
    application_id: UUID | None = Query(None),
) -> Response:
    """Export findings in CEF text format for Syslog SIEM collectors."""
    result, content_type = await use_case.execute(
        principal=principal,
        fmt="cef",
        application_id=application_id,
    )
    assert isinstance(result, str)
    return Response(content=result, media_type=content_type)
