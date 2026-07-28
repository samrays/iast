"""The Organization aggregate — the tenant boundary of the entire platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from ..errors import InvalidStateError, LicenseLimitExceededError
from ..value_objects import Slug, new_id


class OrganizationStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    PENDING_DELETION = "PENDING_DELETION"


class LicenseTier(StrEnum):
    TRIAL = "TRIAL"
    TEAM = "TEAM"
    BUSINESS = "BUSINESS"
    ENTERPRISE = "ENTERPRISE"


#: Entitlements per tier. ``-1`` means unlimited.
TIER_ENTITLEMENTS: dict[LicenseTier, dict[str, int | bool]] = {
    LicenseTier.TRIAL: {
        "max_applications": 3,
        "max_agents": 5,
        "max_users": 5,
        "ai_enabled": False,
        "protection_enabled": False,
    },
    LicenseTier.TEAM: {
        "max_applications": 15,
        "max_agents": 50,
        "max_users": 25,
        "ai_enabled": True,
        "protection_enabled": False,
    },
    LicenseTier.BUSINESS: {
        "max_applications": 100,
        "max_agents": 500,
        "max_users": 200,
        "ai_enabled": True,
        "protection_enabled": True,
    },
    LicenseTier.ENTERPRISE: {
        "max_applications": -1,
        "max_agents": -1,
        "max_users": -1,
        "ai_enabled": True,
        "protection_enabled": True,
    },
}


@dataclass(slots=True)
class License:
    """Entitlement held by an organization.

    Enforcement happens in the application layer at the moment of creation, so a downgrade
    never retroactively deletes resources — it only blocks new ones.
    """

    organization_id: UUID
    tier: LicenseTier = LicenseTier.TRIAL
    max_applications: int = 3
    max_agents: int = 5
    max_users: int = 5
    ai_enabled: bool = False
    protection_enabled: bool = False
    valid_until: datetime | None = None
    id: UUID = field(default_factory=new_id)

    @classmethod
    def for_tier(
        cls, organization_id: UUID, tier: LicenseTier, *, valid_until: datetime | None = None
    ) -> License:
        entitlements = TIER_ENTITLEMENTS[tier]
        return cls(
            organization_id=organization_id,
            tier=tier,
            max_applications=int(entitlements["max_applications"]),
            max_agents=int(entitlements["max_agents"]),
            max_users=int(entitlements["max_users"]),
            ai_enabled=bool(entitlements["ai_enabled"]),
            protection_enabled=bool(entitlements["protection_enabled"]),
            valid_until=valid_until,
        )

    def is_valid(self, now: datetime) -> bool:
        return self.valid_until is None or self.valid_until > now

    def check_applications(self, current_count: int) -> None:
        if self.max_applications >= 0 and current_count >= self.max_applications:
            raise LicenseLimitExceededError("applications", self.max_applications)

    def check_agents(self, current_count: int) -> None:
        if self.max_agents >= 0 and current_count >= self.max_agents:
            raise LicenseLimitExceededError("agents", self.max_agents)

    def check_users(self, current_count: int) -> None:
        if self.max_users >= 0 and current_count >= self.max_users:
            raise LicenseLimitExceededError("users", self.max_users)


@dataclass(slots=True)
class Organization:
    """A tenant.

    Every tenant-owned row in the database carries this entity's id, and every repository
    that touches such a row is scoped to it (ADR-0003).
    """

    name: str
    slug: Slug
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    settings: dict[str, Any] = field(default_factory=dict)
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    deletion_scheduled_at: datetime | None = None

    def __post_init__(self) -> None:
        self.name = (self.name or "").strip()
        if not self.name:
            raise InvalidStateError("An organization must have a name.")
        if len(self.name) > 200:
            raise InvalidStateError("An organization name may be at most 200 characters.")

    @property
    def is_active(self) -> bool:
        return self.status is OrganizationStatus.ACTIVE

    def rename(self, name: str) -> None:
        candidate = (name or "").strip()
        if not candidate:
            raise InvalidStateError("An organization must have a name.")
        self.name = candidate

    def suspend(self, reason: str) -> None:
        if self.status is OrganizationStatus.PENDING_DELETION:
            raise InvalidStateError("An organization pending deletion cannot be suspended.")
        self.status = OrganizationStatus.SUSPENDED
        self.settings["suspension_reason"] = reason

    def reactivate(self) -> None:
        if self.status is OrganizationStatus.PENDING_DELETION:
            raise InvalidStateError(
                "Deletion must be cancelled before the organization can be reactivated."
            )
        self.status = OrganizationStatus.ACTIVE
        self.settings.pop("suspension_reason", None)

    def schedule_deletion(self, at: datetime) -> None:
        """Begin the two-phase tenant deletion described in docs/03-data-model.md."""
        self.status = OrganizationStatus.PENDING_DELETION
        self.deletion_scheduled_at = at

    def cancel_deletion(self) -> None:
        if self.status is not OrganizationStatus.PENDING_DELETION:
            raise InvalidStateError("This organization is not scheduled for deletion.")
        self.status = OrganizationStatus.ACTIVE
        self.deletion_scheduled_at = None
