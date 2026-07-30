"""Installed rule catalogue bundles.

Not tenant-scoped and no row-level security, unlike every other table here: the catalogue is
published by the vendor. A tenant-writable rule set would let one organization decide what the
engine detects for everyone.

Revision ID: 0005_rule_bundles
Revises: 0004_rule_settings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_rule_bundles"
down_revision: str | None = "0004_rule_settings"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "rule_bundles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        # Unique: installing the same version twice is the rollback/replay case, and the
        # constraint catches it even if the application check is somehow bypassed.
        sa.Column("version", sa.Integer(), nullable=False, unique=True),
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("published_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "installed_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("rule_bundles")
