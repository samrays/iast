"""Per-tenant rule enablement.

Separate from the rule catalogue on purpose: a customer switching a rule off is not the
catalogue changing. It must not reach another tenant, and it must survive the next bundle
upgrade rather than being silently reverted.

Revision ID: 0004_rule_settings
Revises: 0003_would_block
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_rule_settings"
down_revision: str | None = "0003_would_block"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "tenant_rule_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "disabled",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Row-level security, as for every tenant-owned table. The predicate is the backstop that
    # survives a query somebody forgets to scope; the rls_bypass flag is what lets the
    # migration and the operational CLI work as the app role rather than a superuser.
    op.execute("ALTER TABLE tenant_rule_settings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_rule_settings FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_rule_settings_isolation ON tenant_rule_settings
        USING (
            organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
            OR current_setting('app.rls_bypass', true) = 'on'
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_rule_settings_isolation ON tenant_rule_settings")
    op.drop_table("tenant_rule_settings")
