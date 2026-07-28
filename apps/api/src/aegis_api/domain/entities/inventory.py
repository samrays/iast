"""Application inventory and agent fleet.

An :class:`Application` is a logical service. It is deployed into one or more
:class:`ApplicationEnvironment` instances, and each environment is reported on by one or
more :class:`Agent` processes. Findings attach to the application (so the same flaw in
staging and production is one flaw) while telemetry attaches to the environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from ..errors import InvalidStateError
from ..policies import InventoryPolicy
from ..value_objects import Slug, new_id


class Language(StrEnum):
    JAVA = "JAVA"
    DOTNET = "DOTNET"
    NODE = "NODE"
    PYTHON = "PYTHON"
    GO = "GO"


class Criticality(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> float:
        """Multiplier applied to risk scores in Phase 5."""
        return {"LOW": 0.6, "MEDIUM": 0.8, "HIGH": 1.0, "CRITICAL": 1.25}[self.value]


class EnvironmentKind(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    QA = "QA"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class ProtectionMode(StrEnum):
    """Application Detection & Response mode.

    Defaults to ``MONITOR`` everywhere. ``BLOCK`` is opt-in per environment and, per the
    threat model, requires a completed monitor-mode soak before it may be enabled.
    """

    OFF = "OFF"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"


class AgentStatus(StrEnum):
    REGISTERED = "REGISTERED"
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    DISABLED = "DISABLED"


@dataclass(slots=True)
class Application:
    """A service under test."""

    organization_id: UUID
    name: str
    slug: Slug
    language: Language
    criticality: Criticality = Criticality.MEDIUM
    tags: tuple[str, ...] = ()
    repository_url: str | None = None
    description: str = ""
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        self.name = (self.name or "").strip()
        if not self.name:
            raise InvalidStateError("An application must have a name.")
        if len(self.name) > 120:
            raise InvalidStateError("An application name may be at most 120 characters.")
        self.description = (self.description or "").strip()[:1000]

    def update(
        self,
        *,
        name: str | None = None,
        criticality: Criticality | None = None,
        tags: list[str] | None = None,
        repository_url: str | None = None,
        description: str | None = None,
        policy: InventoryPolicy | None = None,
    ) -> None:
        if name is not None:
            candidate = name.strip()
            if not candidate:
                raise InvalidStateError("An application must have a name.")
            self.name = candidate[:120]
        if criticality is not None:
            self.criticality = criticality
        if tags is not None:
            normalized = (policy or InventoryPolicy()).normalize_tags(tags)
            self.tags = tuple(normalized)
        if repository_url is not None:
            self.repository_url = repository_url.strip()[:500] or None
        if description is not None:
            self.description = description.strip()[:1000]


@dataclass(slots=True)
class ApplicationEnvironment:
    """A deployment target of an application."""

    organization_id: UUID
    application_id: UUID
    kind: EnvironmentKind
    internet_facing: bool = False
    protection_mode: ProtectionMode = ProtectionMode.MONITOR
    soak_completed_at: datetime | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    #: Monitor-mode soak required before blocking may be enabled in production.
    REQUIRED_SOAK_DAYS = 14

    @property
    def exposure_weight(self) -> float:
        """Contribution of this environment to a finding's risk score (Phase 5)."""
        base = {
            EnvironmentKind.DEVELOPMENT: 0.3,
            EnvironmentKind.QA: 0.4,
            EnvironmentKind.STAGING: 0.7,
            EnvironmentKind.PRODUCTION: 1.0,
        }[self.kind]
        return base * (1.3 if self.internet_facing else 1.0)

    def set_protection_mode(self, mode: ProtectionMode, now: datetime) -> None:
        """Change ADR mode, enforcing the soak requirement before blocking.

        Blocking a legitimate request is a customer-visible incident, so production may
        only start blocking after a monitor-mode period long enough to surface false
        positives (see docs/02-threat-model.md §4.3).
        """
        if (
            mode is ProtectionMode.BLOCK
            and self.kind is EnvironmentKind.PRODUCTION
            and not self._soak_satisfied(now)
        ):
            raise InvalidStateError(
                f"Blocking requires {self.REQUIRED_SOAK_DAYS} days in monitor mode first."
            )
        if mode is not ProtectionMode.MONITOR:
            pass
        elif self.protection_mode is not ProtectionMode.MONITOR:
            # Entering monitor mode (re)starts the soak clock.
            self.soak_completed_at = now + timedelta(days=self.REQUIRED_SOAK_DAYS)
        self.protection_mode = mode

    def _soak_satisfied(self, now: datetime) -> bool:
        return self.soak_completed_at is not None and self.soak_completed_at <= now


@dataclass(slots=True)
class Agent:
    """A runtime agent process reporting into the platform.

    Identity is the ``fingerprint`` the agent computes from stable host and process
    attributes, so a restarting pod reuses its registration instead of creating a new agent
    row on every deploy.
    """

    organization_id: UUID
    application_environment_id: UUID
    fingerprint: str
    hostname: str
    agent_version: str
    runtime_version: str
    language: Language
    status: AgentStatus = AgentStatus.REGISTERED
    config_version: str = "0"
    last_seen_at: datetime | None = None
    cpu_overhead_pct: float | None = None
    memory_mb: int | None = None
    events_sent: int = 0
    events_dropped: int = 0
    health: dict[str, Any] = field(default_factory=dict)
    pinned_version: str | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None

    #: An agent that has not been heard from for this long is considered offline. Three
    #: missed 30-second heartbeats — tolerant of one lost packet, still prompt.
    OFFLINE_AFTER_SECONDS = 90
    #: Overhead above which the agent is reported as degraded (docs/05 §6).
    DEGRADED_OVERHEAD_PCT = 5.0

    def __post_init__(self) -> None:
        self.fingerprint = (self.fingerprint or "").strip()
        if not self.fingerprint:
            raise InvalidStateError("An agent must present a fingerprint.")
        self.hostname = (self.hostname or "unknown")[:255]

    def record_heartbeat(
        self,
        *,
        now: datetime,
        cpu_overhead_pct: float | None = None,
        memory_mb: int | None = None,
        events_sent: int = 0,
        events_dropped: int = 0,
        health: dict[str, Any] | None = None,
    ) -> None:
        if self.status is AgentStatus.DISABLED:
            raise InvalidStateError("A disabled agent may not report.")
        self.last_seen_at = now
        self.cpu_overhead_pct = cpu_overhead_pct
        self.memory_mb = memory_mb
        self.events_sent += max(0, events_sent)
        self.events_dropped += max(0, events_dropped)
        if health is not None:
            self.health = health

        degraded = (
            cpu_overhead_pct is not None and cpu_overhead_pct > self.DEGRADED_OVERHEAD_PCT
        ) or bool(health and health.get("hooks_disabled"))
        self.status = AgentStatus.DEGRADED if degraded else AgentStatus.ONLINE

    def evaluate_liveness(self, now: datetime) -> None:
        """Demote to OFFLINE when heartbeats stop. Called by the fleet-sweep job."""
        if self.status is AgentStatus.DISABLED:
            return
        if self.last_seen_at is None:
            return
        if (now - self.last_seen_at).total_seconds() > self.OFFLINE_AFTER_SECONDS:
            self.status = AgentStatus.OFFLINE

    def disable(self) -> None:
        self.status = AgentStatus.DISABLED

    def enable(self) -> None:
        if self.status is AgentStatus.DISABLED:
            self.status = AgentStatus.REGISTERED

    def pin_version(self, version: str | None) -> None:
        self.pinned_version = (version or "").strip()[:40] or None

    def apply_config(self, version: str) -> None:
        self.config_version = version
