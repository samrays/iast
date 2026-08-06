"""Agent fleet: registration, heartbeat, configuration and administration.

Registration is the one place an unattended process joins a tenant, so it authenticates
with an API key holding ``agent:write`` and is bounded by the licence agent count.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ..domain.entities import (
    ActorType,
    Agent,
    AgentStatus,
    Application,
    ApplicationEnvironment,
    EnvironmentKind,
    Language,
)
from ..domain.entities.audit import AuditAction
from ..domain.errors import AuthenticationError, NotFoundError, TokenError, ValidationError
from ..domain.permissions import Permission
from ..domain.ports import AccessTokenCodec, Clock, UnitOfWork
from ..domain.value_objects import Slug
from .audit_recorder import AuditRecorder
from .auth import AGENT_AUDIENCE
from .context import Principal, RequestContext
from .dto import AgentConfiguration, AgentRegistration, AgentSummary, Page

#: How often an agent must check in. Three missed intervals mark it offline.
HEARTBEAT_INTERVAL_SECONDS = 30
#: Agent credentials are short-lived and renewed through the heartbeat.
AGENT_TOKEN_TTL_SECONDS = 86_400

#: Default redaction deny-list applied in the agent before anything is transmitted (T-04).
DEFAULT_REDACT_KEYS = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "session",
    "ssn",
    "card",
    "cvv",
    "pan",
    "private_key",
]

#: Rules enabled by default on a new agent. Detection rule bundles are versioned data
#: (ADR-0005); this list is the Phase 4/5 starting set.
DEFAULT_ENABLED_RULES = [
    "sql-injection",
    "command-injection",
    "path-traversal",
    "unsafe-deserialization",
    "xxe",
    "reflected-xss",
    "ssrf",
    "ldap-injection",
    "xpath-injection",
    "open-redirect",
    "weak-cryptography",
    "insecure-cookie",
    "missing-security-headers",
    "verbose-error-response",
    "hardcoded-credentials",
    "sensitive-data-in-log",
]


def _summary(agent: Agent) -> AgentSummary:
    return AgentSummary(
        id=agent.id,
        application_environment_id=agent.application_environment_id,
        fingerprint=agent.fingerprint,
        hostname=agent.hostname,
        language=agent.language.value,
        agent_version=agent.agent_version,
        runtime_version=agent.runtime_version,
        status=agent.status.value,
        config_version=agent.config_version,
        cpu_overhead_pct=agent.cpu_overhead_pct,
        memory_mb=agent.memory_mb,
        events_sent=agent.events_sent,
        events_dropped=agent.events_dropped,
        pinned_version=agent.pinned_version,
        last_seen_at=agent.last_seen_at,
        created_at=agent.created_at,
    )


class RegisterAgent:
    """Register (or re-register) an agent process.

    Identity is the fingerprint the agent derives from stable host attributes, so a pod
    restart reuses its row instead of creating a new one on every deploy. The application
    and environment are created on first sight — an agent showing up for an unknown service
    is the normal way inventory gets populated.
    """

    def __init__(self, uow: UnitOfWork, clock: Clock, codec: AccessTokenCodec) -> None:
        self._uow = uow
        self._clock = clock
        self._codec = codec

    async def execute(
        self,
        *,
        principal: Principal,
        application_name: str,
        environment: EnvironmentKind,
        language: Language,
        fingerprint: str,
        hostname: str,
        agent_version: str,
        runtime_version: str,
        context: RequestContext,
    ) -> AgentRegistration:
        principal.require(Permission.AGENT_WRITE)
        now = self._clock.now()

        if not fingerprint.strip():
            raise ValidationError("A fingerprint is required.", field="fingerprint")

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)

            application = await self._ensure_application(uow, principal, application_name, language)
            app_environment = await self._ensure_environment(
                uow, principal, application, environment
            )

            agent = await uow.agents.get_by_fingerprint(fingerprint.strip())
            if agent is None:
                license_ = await uow.licenses.get_for_organization(principal.organization_id)
                if license_ is not None:
                    license_.check_agents(await uow.agents.count())

                agent = Agent(
                    organization_id=principal.organization_id,
                    application_environment_id=app_environment.id,
                    fingerprint=fingerprint.strip(),
                    hostname=hostname,
                    agent_version=agent_version,
                    runtime_version=runtime_version,
                    language=language,
                    config_version=self._config_version(app_environment, now),
                    created_at=now,
                )
                await uow.agents.add(agent)
                await AuditRecorder(uow.audit).record(
                    principal=principal,
                    action=AuditAction.AGENT_REGISTERED.value,
                    resource_type="agent",
                    resource_id=agent.id,
                    metadata={
                        "application": application.name,
                        "environment": environment.value,
                        "language": language.value,
                        "agent_version": agent_version,
                        "hostname": agent.hostname,
                    },
                )
            else:
                agent.hostname = hostname[:255]
                agent.agent_version = agent_version
                agent.runtime_version = runtime_version
                agent.application_environment_id = app_environment.id
                agent.config_version = self._config_version(app_environment, now)
                agent.enable()
                await uow.agents.update(agent)

            token = self._codec.issue_challenge(
                subject=agent.id,
                organization_id=principal.organization_id,
                ttl_seconds=AGENT_TOKEN_TTL_SECONDS,
                now=now,
                purpose="agent",
            )
            await uow.commit()

            return AgentRegistration(
                agent=_summary(agent),
                agent_token=token,
                agent_token_expires_at=now + timedelta(seconds=AGENT_TOKEN_TTL_SECONDS),
                config_version=agent.config_version,
                heartbeat_interval_seconds=HEARTBEAT_INTERVAL_SECONDS,
            )

    @staticmethod
    def _config_version(environment: ApplicationEnvironment, now: datetime) -> str:
        """A version string that changes whenever the delivered configuration would.

        The agent compares this against what it holds and re-fetches only on a change,
        which is what keeps the heartbeat cheap.
        """
        updated = environment.updated_at or environment.created_at or now
        return f"{environment.protection_mode.value}-{int(updated.timestamp())}"

    async def _ensure_application(
        self, uow: UnitOfWork, principal: Principal, name: str, language: Language
    ) -> Application:
        slug = Slug.from_name(name)
        application = await uow.applications.get_by_slug(slug)
        if application is not None:
            return application

        license_ = await uow.licenses.get_for_organization(principal.organization_id)
        if license_ is not None:
            license_.check_applications(await uow.applications.count())

        application = Application(
            organization_id=principal.organization_id,
            name=name.strip(),
            slug=slug,
            language=language,
        )
        await uow.applications.add(application)
        await AuditRecorder(uow.audit).record(
            principal=principal,
            action=AuditAction.APPLICATION_CREATED.value,
            resource_type="application",
            resource_id=application.id,
            metadata={"name": application.name, "discovered_by": "agent"},
        )
        return application

    @staticmethod
    async def _ensure_environment(
        uow: UnitOfWork, principal: Principal, application: Application, kind: EnvironmentKind
    ) -> ApplicationEnvironment:
        existing = await uow.environments.find(application.id, kind.value)
        if existing is not None:
            return existing
        environment = ApplicationEnvironment(
            organization_id=principal.organization_id,
            application_id=application.id,
            kind=kind,
        )
        await uow.environments.add(environment)
        return environment


class RecordHeartbeat:
    """Accept an agent check-in and hand back the current configuration version."""

    def __init__(self, uow: UnitOfWork, clock: Clock) -> None:
        self._uow = uow
        self._clock = clock

    async def execute(
        self,
        *,
        principal: Principal,
        cpu_overhead_pct: float | None,
        memory_mb: int | None,
        events_sent: int,
        events_dropped: int,
        health: dict[str, Any] | None,
    ) -> AgentSummary:
        if principal.kind is not ActorType.AGENT or principal.agent_id is None:
            raise AuthenticationError("Only an agent credential may report a heartbeat.")
        now = self._clock.now()

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            agent = await uow.agents.get(principal.agent_id)
            if agent is None:
                raise NotFoundError("Agent", principal.agent_id)

            agent.record_heartbeat(
                now=now,
                cpu_overhead_pct=cpu_overhead_pct,
                memory_mb=memory_mb,
                events_sent=events_sent,
                events_dropped=events_dropped,
                health=health,
            )
            environment = await uow.environments.get(agent.application_environment_id)
            if environment is not None:
                agent.apply_config(RegisterAgent._config_version(environment, now))

            await uow.agents.update(agent)
            await uow.commit()
            return _summary(agent)


class GetAgentConfiguration:
    """Serve the configuration an agent should be running with."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal) -> AgentConfiguration:
        if principal.kind is not ActorType.AGENT or principal.agent_id is None:
            raise AuthenticationError("Only an agent credential may fetch agent configuration.")

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            agent = await uow.agents.get(principal.agent_id)
            if agent is None:
                raise NotFoundError("Agent", principal.agent_id)
            environment = await uow.environments.get(agent.application_environment_id)
            if environment is None:  # pragma: no cover - referential integrity
                raise NotFoundError("Environment", agent.application_environment_id)

            organization = await uow.organizations.get(principal.organization_id)
            settings: dict[str, Any] = organization.settings if organization else {}
            capture = str(settings.get("capture_request_body", "TRUNCATED"))
            extra_keys = [str(k).lower() for k in settings.get("redact_keys", [])]

            return AgentConfiguration(
                config_version=agent.config_version,
                protection_mode=environment.protection_mode.value,
                capture_request_body=capture,
                max_value_length=int(settings.get("max_value_length", 512)),
                redact_keys=sorted(set(DEFAULT_REDACT_KEYS) | set(extra_keys)),
                cpu_budget_pct=float(settings.get("cpu_budget_pct", 5.0)),
                enabled_rules=list(settings.get("enabled_rules", DEFAULT_ENABLED_RULES)),
                heartbeat_interval_seconds=HEARTBEAT_INTERVAL_SECONDS,
            )


class ResolveAgentPrincipal:
    """Turn an agent token into a principal with only the ``agent:report`` capability.

    The audience separation matters: an agent token presented to a user endpoint must be
    rejected outright (threat T-06).
    """

    def __init__(self, uow: UnitOfWork, clock: Clock, codec: AccessTokenCodec) -> None:
        self._uow = uow
        self._clock = clock
        self._codec = codec

    async def execute(self, *, token: str, context: RequestContext) -> Principal:
        claims = self._codec.decode(token, audience=AGENT_AUDIENCE)
        if claims.get("purpose") != "agent":
            raise TokenError("This token is not an agent credential.")

        agent_id = UUID(str(claims["sub"]))
        organization_id = UUID(str(claims["org"]))

        async with self._uow as uow:
            await uow.bind_tenant(organization_id)
            agent = await uow.agents.get(agent_id)
            if agent is None or agent.status is AgentStatus.DISABLED:
                raise AuthenticationError

            return Principal(
                kind=ActorType.AGENT,
                organization_id=organization_id,
                permissions=frozenset(),
                agent_id=agent_id,
                label=f"agent:{agent.hostname}",
                mfa_satisfied=True,
                context=context,
            )


class ListAgents:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, limit: int, cursor: str | None, status: str | None
    ) -> Page[AgentSummary]:
        principal.require(Permission.AGENT_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            agents, next_cursor = await uow.agents.list_all(
                limit=limit, cursor=cursor, status=status
            )
            return Page(items=[_summary(a) for a in agents], next_cursor=next_cursor, limit=limit)


class GetAgent:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal, agent_id: UUID) -> AgentSummary:
        principal.require(Permission.AGENT_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            agent = await uow.agents.get(agent_id)
            if agent is None:
                raise NotFoundError("Agent", agent_id)
            return _summary(agent)


class UpdateAgent:
    """Enable, disable or pin an agent — the fleet controls a platform team needs."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        agent_id: UUID,
        enabled: bool | None,
        pinned_version: str | None,
    ) -> AgentSummary:
        principal.require(Permission.AGENT_WRITE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            agent = await uow.agents.get(agent_id)
            if agent is None:
                raise NotFoundError("Agent", agent_id)

            changed: dict[str, Any] = {}
            if enabled is not None:
                agent.enable() if enabled else agent.disable()
                changed["enabled"] = enabled
            if pinned_version is not None:
                agent.pin_version(pinned_version)
                changed["pinned_version"] = agent.pinned_version

            await uow.agents.update(agent)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.AGENT_UPDATED.value,
                resource_type="agent",
                resource_id=agent.id,
                metadata=changed,
            )
            await uow.commit()
            return _summary(agent)
