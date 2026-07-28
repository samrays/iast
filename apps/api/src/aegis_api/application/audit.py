"""Reading and verifying the audit log."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ..domain.entities import AuditEvent
from ..domain.entities.audit import AuditAction
from ..domain.permissions import Permission
from ..domain.ports import UnitOfWork
from .audit_recorder import AuditRecorder
from .context import Principal
from .dto import AuditEventSummary, ChainVerification, Page


def _summary(event: AuditEvent) -> AuditEventSummary:
    return AuditEventSummary(
        id=event.id,
        sequence=event.sequence,
        action=event.action,
        actor_type=event.actor_type.value,
        actor_user_id=event.actor_user_id,
        actor_label=event.actor_label,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        outcome=event.outcome.value,
        ip_address=event.ip_address,
        request_id=event.request_id,
        metadata=dict(event.metadata),
        occurred_at=event.occurred_at,
    )


class ListAuditEvents:
    """Browse the chain.

    Reading the audit log is itself audited — that is one of the few reads worth recording,
    because an attacker checking what has been noticed is a strong signal.
    """

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        limit: int,
        cursor: str | None,
        action: str | None = None,
        actor_user_id: UUID | None = None,
        occurred_after: datetime | None = None,
    ) -> Page[AuditEventSummary]:
        principal.require(Permission.AUDIT_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            events, next_cursor = await uow.audit.list_all(
                limit=limit,
                cursor=cursor,
                action=action,
                actor_user_id=actor_user_id,
                occurred_after=occurred_after,
            )
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.AUDIT_LOG_READ.value,
                resource_type="audit",
                metadata={"filters": {"action": action, "actor_user_id": str(actor_user_id or "")}},
            )
            await uow.commit()
            return Page(items=[_summary(e) for e in events], next_cursor=next_cursor, limit=limit)


class VerifyAuditChain:
    """Walk the hash chain and report whether it is intact (threat T-11)."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal, limit: int | None = None) -> ChainVerification:
        principal.require(Permission.AUDIT_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            intact, checked, broken_at = await uow.audit.verify_chain(limit=limit)
            return ChainVerification(
                intact=intact, entries_checked=checked, first_broken_sequence=broken_at
            )
