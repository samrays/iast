"""The permission catalogue and the system role definitions.

Permissions are the single vocabulary of authorization. Nothing in the codebase checks a
role name — roles are bundles of permissions, and only permissions are ever checked. That
keeps custom roles first-class: a customer-defined role is indistinguishable from a system
role at the point of enforcement.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class Permission(StrEnum):
    """Every action the platform can authorize.

    Naming is ``resource:verb``. Verbs are deliberately coarse — a finer-grained scheme
    produces a permission matrix nobody can reason about, which is itself a security risk.
    """

    # Organization
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"
    ORG_DELETE = "org:delete"

    # Members and roles
    USER_INVITE = "user:invite"
    USER_REMOVE = "user:remove"
    ROLE_WRITE = "role:write"

    # Application inventory
    APP_READ = "app:read"
    APP_WRITE = "app:write"
    APP_DELETE = "app:delete"

    # Agent fleet
    AGENT_READ = "agent:read"
    AGENT_WRITE = "agent:write"

    # Findings (Phase 5)
    FINDING_READ = "finding:read"
    FINDING_TRIAGE = "finding:triage"
    FINDING_SUPPRESS = "finding:suppress"

    # Policy and protection (Phase 5)
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"

    # Reporting and compliance (Phase 7)
    REPORT_READ = "report:read"
    REPORT_WRITE = "report:write"

    # Governance
    AUDIT_READ = "audit:read"
    SETTINGS_WRITE = "settings:write"

    # AI (Phase 6)
    AI_RUN = "ai:run"
    AI_APPROVE = "ai:approve"


#: Permissions whose holders can change who holds permissions. Roles containing any of
#: these are "privileged"; MFA can be required for them via configuration.
PRIVILEGED_PERMISSIONS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.ROLE_WRITE,
        Permission.USER_INVITE,
        Permission.USER_REMOVE,
        Permission.ORG_DELETE,
        Permission.SETTINGS_WRITE,
    }
)

#: Permissions that must never be granted through a custom role, because holding them is
#: equivalent to owning the organization.
OWNER_ONLY_PERMISSIONS: Final[frozenset[Permission]] = frozenset({Permission.ORG_DELETE})


class SystemRole(StrEnum):
    """Roles seeded into every new organization."""

    OWNER = "Owner"
    ADMIN = "Admin"
    SECURITY_ANALYST = "Security Analyst"
    DEVELOPER = "Developer"
    VIEWER = "Viewer"


_READ_ONLY: Final[frozenset[Permission]] = frozenset(
    {
        Permission.ORG_READ,
        Permission.APP_READ,
        Permission.AGENT_READ,
        Permission.FINDING_READ,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
    }
)

SYSTEM_ROLE_PERMISSIONS: Final[dict[SystemRole, frozenset[Permission]]] = {
    SystemRole.OWNER: frozenset(Permission),
    SystemRole.ADMIN: frozenset(Permission) - OWNER_ONLY_PERMISSIONS,
    SystemRole.SECURITY_ANALYST: _READ_ONLY
    | frozenset(
        {
            Permission.FINDING_TRIAGE,
            Permission.FINDING_SUPPRESS,
            Permission.POLICY_WRITE,
            Permission.AGENT_WRITE,
            Permission.REPORT_WRITE,
            Permission.AUDIT_READ,
            Permission.AI_RUN,
            Permission.AI_APPROVE,
        }
    ),
    SystemRole.DEVELOPER: _READ_ONLY
    | frozenset({Permission.APP_WRITE, Permission.FINDING_TRIAGE, Permission.AI_RUN}),
    SystemRole.VIEWER: _READ_ONLY,
}

SYSTEM_ROLE_DESCRIPTIONS: Final[dict[SystemRole, str]] = {
    SystemRole.OWNER: "Full control, including deleting the organization. Assigned to the creator.",
    SystemRole.ADMIN: "Full control except deleting the organization.",
    SystemRole.SECURITY_ANALYST: (
        "Triages findings, tunes protection policy, manages agents and reads the audit log."
    ),
    SystemRole.DEVELOPER: "Manages their applications and triages findings against them.",
    SystemRole.VIEWER: "Read-only access to inventory, findings and reports.",
}


def parse_permission(raw: str) -> Permission:
    """Parse a stored or submitted permission string.

    Unknown values raise ``ValueError``. Silently dropping an unrecognized permission would
    make a typo in a role definition fail open at some later date.
    """
    try:
        return Permission(raw)
    except ValueError as exc:
        raise ValueError(f"Unknown permission: {raw!r}") from exc


def is_privileged(permissions: frozenset[Permission]) -> bool:
    return bool(permissions & PRIVILEGED_PERMISSIONS)
