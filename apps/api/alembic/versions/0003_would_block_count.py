"""Count the requests blocking mode would have stopped.

A monitor-mode soak is only decidable if someone can see its blast radius before turning
blocking on. That number is how often the agent *would* have interrupted a real request, and
it needs its own column: folding it into occurrence_count would conflate "this flaw is reached
often" with "this flaw is under attack".

Revision ID: 0003_would_block
Revises: 0002_findings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0003_would_block"
down_revision: str | None = "0002_findings"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "would_block_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "would_block_count")
