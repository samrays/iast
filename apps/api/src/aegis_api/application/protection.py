"""Application service for managing tenant application protection policies."""

from __future__ import annotations

from datetime import datetime
from typing import Callable
from uuid import UUID

from ..domain.entities.protection import ProtectionMode, ProtectionPolicy
from ..domain.permissions import Permission
from ..domain.ports import Clock, UnitOfWork
from .context import Principal


class ManageProtectionPolicy:
    """Read and update application protection policy (OFF, MONITOR, BLOCK)."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork], clock: Clock) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def get_policy(self, principal: Principal, application_id: UUID) -> ProtectionPolicy:
        principal.require_permission(Permission.APPLICATION_READ)
        now = self._clock.now()

        async with self._uow_factory() as uow:
            await uow.bind_tenant(principal.organization_id)
            # Default policy if not found
            return ProtectionPolicy.create(
                organization_id=principal.organization_id,
                application_id=application_id,
                mode=ProtectionMode.MONITOR,
                now=now,
            )

    async def update_mode(
        self,
        principal: Principal,
        application_id: UUID,
        new_mode: ProtectionMode,
    ) -> ProtectionPolicy:
        principal.require_permission(Permission.APPLICATION_WRITE)
        now = self._clock.now()

        policy = await self.get_policy(principal, application_id)
        policy.transition_to(new_mode, now)
        return policy
