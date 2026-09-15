"""Protection policy domain entity — action modes (OFF, MONITOR, BLOCK) and soak duration governance."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from ..errors import InvalidStateError
from ..value_objects import new_id

SOAK_DURATION_HOURS = 336  # Mandatory 14-day (336h) soak duration before BLOCK mode can be enabled


class ProtectionMode(StrEnum):
    OFF = "OFF"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"


@dataclass
class ProtectionPolicy:
    """Configures enforcement mode for a tenant's application or environment."""

    id: UUID
    organization_id: UUID
    application_id: UUID
    mode: ProtectionMode = ProtectionMode.MONITOR
    soak_started_at: datetime = field(default_factory=datetime.now)
    would_block_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    @classmethod
    def create(
        self,
        organization_id: UUID,
        application_id: UUID,
        mode: ProtectionMode = ProtectionMode.MONITOR,
        now: datetime | None = None,
    ) -> ProtectionPolicy:
        current_time = now or datetime.now()
        return ProtectionPolicy(
            id=new_id(),
            organization_id=organization_id,
            application_id=application_id,
            mode=mode,
            soak_started_at=current_time,
            would_block_count=0,
            created_at=current_time,
            updated_at=current_time,
        )

    def transition_to(self, new_mode: ProtectionMode, now: datetime) -> None:
        """Enforce mandatory soak duration before transitioning to BLOCK mode."""
        if new_mode == ProtectionMode.BLOCK:
            if self.mode == ProtectionMode.OFF:
                raise InvalidStateError(
                    "Cannot transition directly from OFF to BLOCK. Enable MONITOR mode first for a 24h soak."
                )
            if self.mode == ProtectionMode.MONITOR:
                soak_elapsed = now - self.soak_started_at
                if soak_elapsed < timedelta(hours=SOAK_DURATION_HOURS):
                    hours_left = round((timedelta(hours=SOAK_DURATION_HOURS) - soak_elapsed).total_seconds() / 3600, 1)
                    raise InvalidStateError(
                        f"Cannot transition to BLOCK mode. Soak period incomplete ({hours_left}h remaining)."
                    )

        if new_mode == ProtectionMode.MONITOR and self.mode != ProtectionMode.MONITOR:
            self.soak_started_at = now

        self.mode = new_mode
        self.updated_at = now

    def record_would_block(self) -> None:
        """Increment count of attack events that would have been blocked in MONITOR mode."""
        self.would_block_count += 1
