"""In-memory event stream broadcaster for Server-Sent Events (SSE)."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any
from uuid import UUID


class FindingEventBroadcaster:
    """Tenant-scoped in-memory event broadcaster for real-time finding streaming."""

    def __init__(self) -> None:
        self._subscribers: dict[UUID, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)

    def subscribe(self, organization_id: UUID) -> asyncio.Queue[dict[str, Any]]:
        """Register a client queue to receive live finding events for an organization."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers[organization_id].add(queue)
        return queue

    def unsubscribe(self, organization_id: UUID, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Unregister a client queue when an SSE connection closes."""
        self._subscribers[organization_id].discard(queue)
        if not self._subscribers[organization_id]:
            self._subscribers.pop(organization_id, None)

    def publish(self, organization_id: UUID, event_data: dict[str, Any]) -> None:
        """Publish a finding event to all active subscribers of the organization."""
        queues = list(self._subscribers.get(organization_id, set()))
        for queue in queues:
            try:
                queue.put_nowait(event_data)
            except asyncio.QueueFull:
                # Discard oldest message if client is slow
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                queue.put_nowait(event_data)


# Global singleton broadcaster for findings events
findings_broadcaster = FindingEventBroadcaster()
