"""Detection rule catalogue routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ....application.rules import ListRules, SetRuleEnabled
from ....domain.permissions import Permission
from ..dependencies import ContainerDep, PrincipalDep, requires
from ..schemas import RuleResponse, RuleToggleRequest

router = APIRouter(
    prefix="/rules",
    tags=["rules"],
    # Reading the catalogue is a policy read. Changing it is checked per-route, because
    # switching detection off is a materially different act from looking at what is on.
    dependencies=[Depends(requires(Permission.POLICY_READ))],
)


@router.get("", response_model=list[RuleResponse], summary="The catalogue, worst first")
async def list_rules(principal: PrincipalDep, container: ContainerDep) -> list[RuleResponse]:
    views = await ListRules(container.unit_of_work()).execute(principal=principal)
    return [RuleResponse.of(view) for view in views]


@router.put(
    "/{rule_key}",
    response_model=RuleResponse,
    summary="Turn a rule on or off for this organization",
)
async def set_rule_enabled(
    rule_key: str,
    payload: RuleToggleRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> RuleResponse:
    view = await SetRuleEnabled(container.unit_of_work()).execute(
        principal=principal,
        rule_key=rule_key,
        enabled=payload.enabled,
        reason=payload.reason,
    )
    return RuleResponse.of(view)
