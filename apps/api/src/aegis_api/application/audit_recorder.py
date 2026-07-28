"""Helper for writing audit entries from use cases.

Centralized so that every entry carries the same actor, request and context fields, and so
that adding a field to the audit record is one edit rather than forty.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ..domain.entities import ActorType, AuditEvent, AuditOutcome
from ..domain.ports import AuditRepository
from .context import Principal


class AuditRecorder:
    """Appends sealed entries to an organization's audit chain."""

    def __init__(self, repository: AuditRepository) -> None:
        self._repository = repository

    async def record(
        self,
        *,
        principal: Principal | None,
        action: str,
        resource_type: str = "",
        resource_id: str | UUID = "",
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        organization_id: UUID | None = None,
        actor_type: ActorType | None = None,
        actor_user_id: UUID | None = None,
        actor_label: str = "",
        metadata: dict[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str = "",
        request_id: str = "",
    ) -> AuditEvent:
        org_id = organization_id or (principal.organization_id if principal else None)
        if org_id is None:  # pragma: no cover - guarded by callers
            raise ValueError("An audit entry requires an organization.")

        context = principal.context if principal else None
        event = AuditEvent(
            organization_id=org_id,
            action=action,
            actor_type=actor_type or (principal.kind if principal else ActorType.SYSTEM),
            actor_user_id=actor_user_id or (principal.user_id if principal else None),
            actor_label=actor_label or (principal.label if principal else ""),
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else "",
            outcome=outcome,
            ip_address=ip_address or (context.ip_address if context else None),
            user_agent=user_agent or (context.user_agent if context else ""),
            request_id=request_id or (context.request_id if context else ""),
            metadata=metadata or {},
        )
        return await self._repository.append(event)
