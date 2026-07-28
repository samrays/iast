"""Phase 2 initial schema: tenancy, identity, RBAC, inventory, fleet and audit.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-27

Creates every Phase 2 table, then applies the row-level-security policies described in
ADR-0003 and revokes UPDATE/DELETE on the audit table so the chain is append-only at the
database level rather than only by convention (threat T-11).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Tables that carry a tenant discriminator and are protected by RLS.
TENANT_TABLES = (
    "licenses",
    "roles",
    "memberships",
    "api_keys",
    "applications",
    "application_environments",
    "agents",
    "audit_events",
)

TIMESTAMP = sa.DateTime(timezone=True)


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", TIMESTAMP, server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", TIMESTAMP, server_default=sa.text("now()"), nullable=False),
    ]


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # --- organizations -------------------------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column(
            "settings", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("deletion_scheduled_at", TIMESTAMP),
        *_timestamps(),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED', 'PENDING_DELETION')",
            name="ck_organizations_organizations_status",
        ),
    )
    op.create_index("ix_organizations_status", "organizations", ["status"])

    # --- licenses ------------------------------------------------------------
    op.create_table(
        "licenses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tier", sa.String(20), nullable=False, server_default="TRIAL"),
        sa.Column("max_applications", sa.Integer, nullable=False, server_default="3"),
        sa.Column("max_agents", sa.Integer, nullable=False, server_default="5"),
        sa.Column("max_users", sa.Integer, nullable=False, server_default="5"),
        sa.Column("ai_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column(
            "protection_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column("valid_until", TIMESTAMP),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_licenses_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("organization_id", name="uq_licenses_organization_id"),
        sa.CheckConstraint(
            "tier IN ('TRIAL', 'TEAM', 'BUSINESS', 'ENTERPRISE')", name="ck_licenses_licenses_tier"
        ),
    )

    # --- users ---------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", postgresql.CITEXT, nullable=False),
        sa.Column("password_hash", sa.Text),
        sa.Column("full_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("is_platform_admin", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("failed_login_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", TIMESTAMP),
        sa.Column("password_changed_at", TIMESTAMP),
        sa.Column("last_login_at", TIMESTAMP),
        *_timestamps(),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'INVITED', 'DISABLED')", name="ck_users_users_status"
        ),
        sa.CheckConstraint("failed_login_count >= 0", name="ck_users_users_failed_login_count"),
    )

    op.create_table(
        "mfa_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("secret_encrypted", sa.Text, nullable=False),
        sa.Column("confirmed", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("consumed_at", TIMESTAMP),
        sa.Column("last_used_at", TIMESTAMP),
        sa.Column("label", sa.String(100)),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_mfa_credentials_user_id_users", ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            "kind IN ('TOTP', 'RECOVERY_CODE')", name="ck_mfa_credentials_mfa_credentials_kind"
        ),
    )
    op.create_index("ix_mfa_credentials_user_id_kind", "mfa_credentials", ["user_id", "kind"])

    # --- sessions ------------------------------------------------------------
    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("refresh_token_hash", sa.String(64), nullable=False),
        sa.Column("user_agent", sa.String(400), nullable=False, server_default=""),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("expires_at", TIMESTAMP, nullable=False),
        sa.Column("rotated_at", TIMESTAMP),
        sa.Column("revoked_at", TIMESTAMP),
        sa.Column("revoked_reason", sa.String(80)),
        sa.Column("replaced_by_id", postgresql.UUID(as_uuid=True)),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_sessions_user_id_users", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_sessions_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("refresh_token_hash", name="uq_sessions_refresh_token_hash"),
    )
    op.create_index("ix_sessions_family_id", "sessions", ["family_id"])
    op.create_index("ix_sessions_user_id_expires_at", "sessions", ["user_id", "expires_at"])
    op.create_index(
        "ix_sessions_active",
        "sessions",
        ["user_id"],
        postgresql_where=sa.text("revoked_at IS NULL AND rotated_at IS NULL"),
    )

    # --- roles and memberships ------------------------------------------------
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("is_system", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column(
            "permissions",
            postgresql.ARRAY(sa.Text),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_roles_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("organization_id", "name", name="uq_roles_organization_id_name"),
    )
    op.create_index("ix_roles_organization_id", "roles", ["organization_id"])

    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True)),
        sa.Column("joined_at", TIMESTAMP),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_memberships_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_memberships_user_id_users", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["invited_by"],
            ["users.id"],
            name="fk_memberships_invited_by_users",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "organization_id", "user_id", name="uq_memberships_organization_id_user_id"
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'INVITED', 'SUSPENDED')", name="ck_memberships_memberships_status"
        ),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index(
        "ix_memberships_organization_id_status", "memberships", ["organization_id", "status"]
    )

    op.create_table(
        "membership_roles",
        sa.Column("membership_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.ForeignKeyConstraint(
            ["membership_id"],
            ["memberships.id"],
            name="fk_membership_roles_membership_id_memberships",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"], name="fk_membership_roles_role_id_roles", ondelete="CASCADE"
        ),
    )

    # --- api keys ------------------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("secret_hash", sa.Text, nullable=False),
        sa.Column(
            "permissions",
            postgresql.ARRAY(sa.Text),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
        sa.Column("expires_at", TIMESTAMP),
        sa.Column("revoked_at", TIMESTAMP),
        sa.Column("last_used_at", TIMESTAMP),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_api_keys_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name="fk_api_keys_created_by_users", ondelete="SET NULL"
        ),
        sa.UniqueConstraint("prefix", name="uq_api_keys_prefix"),
    )
    op.create_index("ix_api_keys_organization_id", "api_keys", ["organization_id"])

    # --- inventory -----------------------------------------------------------
    op.create_table(
        "applications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("language", sa.String(10), nullable=False),
        sa.Column("criticality", sa.String(10), nullable=False, server_default="MEDIUM"),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.Text),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("repository_url", sa.String(500)),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_applications_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("organization_id", "slug", name="uq_applications_organization_id_slug"),
        sa.CheckConstraint(
            "language IN ('JAVA', 'DOTNET', 'NODE', 'PYTHON', 'GO')",
            name="ck_applications_applications_language",
        ),
        sa.CheckConstraint(
            "criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_applications_applications_criticality",
        ),
    )
    op.create_index(
        "ix_applications_organization_id_created_at",
        "applications",
        ["organization_id", "created_at"],
    )
    op.create_index("ix_applications_tags", "applications", ["tags"], postgresql_using="gin")

    op.create_table(
        "application_environments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("internet_facing", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("protection_mode", sa.String(10), nullable=False, server_default="MONITOR"),
        sa.Column("soak_completed_at", TIMESTAMP),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_application_environments_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_application_environments_application_id_applications",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "application_id", "kind", name="uq_application_environments_application_id_kind"
        ),
        sa.CheckConstraint(
            "kind IN ('DEVELOPMENT', 'QA', 'STAGING', 'PRODUCTION')",
            name="ck_application_environments_application_environments_kind",
        ),
        sa.CheckConstraint(
            "protection_mode IN ('OFF', 'MONITOR', 'BLOCK')",
            name="ck_application_environments_application_environments_mode",
        ),
    )
    op.create_index(
        "ix_application_environments_organization_id",
        "application_environments",
        ["organization_id"],
    )

    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("application_environment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False, server_default="unknown"),
        sa.Column("language", sa.String(10), nullable=False),
        sa.Column("agent_version", sa.String(40), nullable=False),
        sa.Column("runtime_version", sa.String(80), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="REGISTERED"),
        sa.Column("config_version", sa.String(80), nullable=False, server_default="0"),
        sa.Column("cpu_overhead_pct", sa.Numeric(5, 2)),
        sa.Column("memory_mb", sa.Integer),
        sa.Column("events_sent", sa.Integer, nullable=False, server_default="0"),
        sa.Column("events_dropped", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "health", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("pinned_version", sa.String(40)),
        sa.Column("last_seen_at", TIMESTAMP),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_agents_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["application_environment_id"],
            ["application_environments.id"],
            name="fk_agents_application_environment_id_application_environments",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("fingerprint", name="uq_agents_fingerprint"),
        sa.CheckConstraint(
            "status IN ('REGISTERED', 'ONLINE', 'DEGRADED', 'OFFLINE', 'DISABLED')",
            name="ck_agents_agents_status",
        ),
        sa.CheckConstraint(
            "language IN ('JAVA', 'DOTNET', 'NODE', 'PYTHON', 'GO')",
            name="ck_agents_agents_language",
        ),
    )
    op.create_index("ix_agents_organization_id_status", "agents", ["organization_id", "status"])
    op.create_index(
        "ix_agents_application_environment_id", "agents", ["application_environment_id"]
    )
    op.create_index("ix_agents_last_seen_at", "agents", ["last_seen_at"])

    # --- audit ---------------------------------------------------------------
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer, nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("actor_type", sa.String(20), nullable=False, server_default="SYSTEM"),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("actor_label", sa.String(200), nullable=False, server_default=""),
        sa.Column("resource_type", sa.String(60), nullable=False, server_default=""),
        sa.Column("resource_id", sa.String(80), nullable=False, server_default=""),
        sa.Column("outcome", sa.String(10), nullable=False, server_default="SUCCESS"),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("user_agent", sa.String(400), nullable=False, server_default=""),
        sa.Column("request_id", sa.String(64), nullable=False, server_default=""),
        sa.Column(
            "metadata", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", TIMESTAMP, nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_audit_events_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_audit_events_actor_user_id_users",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "organization_id", "sequence", name="uq_audit_events_organization_id_sequence"
        ),
        sa.CheckConstraint(
            "outcome IN ('SUCCESS', 'FAILURE', 'DENIED')",
            name="ck_audit_events_audit_events_outcome",
        ),
        sa.CheckConstraint(
            "actor_type IN ('USER', 'API_KEY', 'AGENT', 'SYSTEM')",
            name="ck_audit_events_audit_events_actor_type",
        ),
    )
    op.create_index(
        "ix_audit_events_organization_id_occurred_at",
        "audit_events",
        ["organization_id", "occurred_at"],
    )
    op.create_index(
        "ix_audit_events_actor_user_id_occurred_at",
        "audit_events",
        ["actor_user_id", "occurred_at"],
    )
    op.create_index(
        "ix_audit_events_organization_id_action", "audit_events", ["organization_id", "action"]
    )

    _apply_row_level_security()
    _make_audit_append_only()


def _apply_row_level_security() -> None:
    """Enable and force RLS on every tenant-owned table (ADR-0003).

    ``FORCE`` matters: without it the table owner — which in most deployments is the
    application role — bypasses the policy entirely, making the whole control decorative.

    The ``app.rls_bypass`` escape exists for the single pre-tenant query that resolves which
    organizations a user may sign in to. It is raised around one statement and lowered
    immediately; see ``SqlUnitOfWork.find_active_organizations_for_user``.
    """
    predicate = (
        "organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        " OR current_setting('app.rls_bypass', true) = 'on'"
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def _make_audit_append_only() -> None:
    """Reject UPDATE and DELETE on the audit chain at the database level.

    A trigger rather than a grant, because grants are per-role and a deployment that runs
    migrations and the application as the same role would otherwise have no protection at
    all. Superuser maintenance can still drop the trigger deliberately — that is an audited,
    visible act, which is the point.
    """
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_events_reject_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only (%)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute("""
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();
        """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_reject_mutation()")
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_table("audit_events")
    op.drop_table("agents")
    op.drop_table("application_environments")
    op.drop_table("applications")
    op.drop_table("api_keys")
    op.drop_table("membership_roles")
    op.drop_table("memberships")
    op.drop_table("roles")
    op.drop_table("sessions")
    op.drop_table("mfa_credentials")
    op.drop_table("users")
    op.drop_table("licenses")
    op.drop_table("organizations")
