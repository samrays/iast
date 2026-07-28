"""The authenticated agent."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AgentPrincipal:
    """An agent that has proved possession of a valid, unexpired agent credential.

    Note what is absent: any permission set. An agent token grants exactly one capability —
    reporting its own telemetry — and the gateway exposes nothing else. Separating the
    audience from user tokens is what stops a leaked agent credential from reading a tenant's
    findings (threat T-06).
    """

    agent_id: str
    organization_id: str
    #: Present when the control plane pinned the token to an application environment.
    environment_id: str = ""

    @property
    def label(self) -> str:
        return f"agent:{self.agent_id}"
