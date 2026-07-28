"""Agent fleet routes.

Three principal types meet here and are kept strictly apart:

* ``POST /agents/register`` — authenticated with an **API key** holding ``agent:write``.
* ``POST /agents/heartbeat`` and ``GET /agents/config`` — authenticated with an **agent
  token**, whose audience no user endpoint accepts.
* everything else — authenticated as a **user** with the relevant permission.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from ....application.agents import (
    GetAgent,
    GetAgentConfiguration,
    ListAgents,
    RecordHeartbeat,
    RegisterAgent,
    UpdateAgent,
)
from ....domain.permissions import Permission
from ..dependencies import (
    AgentPrincipalDep,
    ContainerDep,
    ContextDep,
    PrincipalDep,
    SettingsDep,
    requires,
)
from ..schemas import (
    AgentConfigurationResponse,
    AgentHeartbeatRequest,
    AgentRegisterRequest,
    AgentRegistrationResponse,
    AgentResponse,
    PageResponse,
    UpdateAgentRequest,
)

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post(
    "/register",
    response_model=AgentRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(requires(Permission.AGENT_WRITE))],
    summary="Register an agent process and obtain an agent credential",
)
async def register_agent(
    payload: AgentRegisterRequest,
    principal: PrincipalDep,
    container: ContainerDep,
    context: ContextDep,
) -> AgentRegistrationResponse:
    result = await RegisterAgent(
        container.unit_of_work(), container.auth.clock, container.auth.codec
    ).execute(
        principal=principal,
        application_name=payload.application_name,
        environment=payload.environment,
        language=payload.language,
        fingerprint=payload.fingerprint,
        hostname=payload.hostname,
        agent_version=payload.agent_version,
        runtime_version=payload.runtime_version,
        context=context,
    )
    return AgentRegistrationResponse(
        agent=AgentResponse.of(result.agent),
        agent_token=result.agent_token,
        agent_token_expires_at=result.agent_token_expires_at,
        config_version=result.config_version,
        heartbeat_interval_seconds=result.heartbeat_interval_seconds,
    )


@router.post("/heartbeat", response_model=AgentResponse, summary="Agent check-in")
async def heartbeat(
    payload: AgentHeartbeatRequest, principal: AgentPrincipalDep, container: ContainerDep
) -> AgentResponse:
    result = await RecordHeartbeat(container.unit_of_work(), container.auth.clock).execute(
        principal=principal,
        cpu_overhead_pct=payload.cpu_overhead_pct,
        memory_mb=payload.memory_mb,
        events_sent=payload.events_sent,
        events_dropped=payload.events_dropped,
        health=dict(payload.health) if payload.health else None,
    )
    return AgentResponse.of(result)


@router.get(
    "/config",
    response_model=AgentConfigurationResponse,
    summary="The configuration this agent should be running",
)
async def get_config(
    principal: AgentPrincipalDep, container: ContainerDep
) -> AgentConfigurationResponse:
    result = await GetAgentConfiguration(container.unit_of_work()).execute(principal=principal)
    return AgentConfigurationResponse.of(result)


@router.get("", response_model=PageResponse[AgentResponse], summary="List the agent fleet")
async def list_agents(
    principal: PrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
    agent_status: Annotated[str | None, Query(alias="status")] = None,
) -> PageResponse[AgentResponse]:
    page = await ListAgents(container.unit_of_work()).execute(
        principal=principal,
        limit=min(limit, settings.max_page_size),
        cursor=cursor,
        status=agent_status,
    )
    return PageResponse.of(page, [AgentResponse.of(item) for item in page.items])


@router.get("/{agent_id}", response_model=AgentResponse, summary="Get one agent")
async def get_agent(
    agent_id: UUID, principal: PrincipalDep, container: ContainerDep
) -> AgentResponse:
    result = await GetAgent(container.unit_of_work()).execute(
        principal=principal, agent_id=agent_id
    )
    return AgentResponse.of(result)


@router.patch(
    "/{agent_id}",
    response_model=AgentResponse,
    dependencies=[Depends(requires(Permission.AGENT_WRITE))],
    summary="Enable, disable or pin an agent",
)
async def update_agent(
    agent_id: UUID,
    payload: UpdateAgentRequest,
    principal: PrincipalDep,
    container: ContainerDep,
) -> AgentResponse:
    result = await UpdateAgent(container.unit_of_work()).execute(
        principal=principal,
        agent_id=agent_id,
        enabled=payload.enabled,
        pinned_version=payload.pinned_version,
    )
    return AgentResponse.of(result)
