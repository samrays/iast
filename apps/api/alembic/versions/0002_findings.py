"""Findings, occurrences and triage comments.

Phase 5's storage. Three tables with three different mutability rules, deliberately:

* ``findings`` is mutable — a finding's status, score and counters change as it is triaged
  and as it recurs.
* ``finding_occurrences`` is insert-only — evidence of something that happened cannot
  retrospectively have happened differently.
* ``finding_comments`` is append-only at the database level, like the audit chain. Comments
  are the record of how a dismissal was decided, and that record must not be editable after
  an incident makes someone wish it said something else.

Revision ID: 0002_findings
Revises: 0001_initial
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_findings"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: New tenant-owned tables. Each gets the same policy as everything in 0001 (ADR-0003).
TENANT_TABLES = ("findings", "finding_occurrences", "finding_comments")


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_hash", sa.String(length=64), nullable=False),
        sa.Column("rule_key", sa.String(length=60), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("confidence", sa.String(length=10), nullable=False),
        sa.Column("sink_signature", sa.String(length=400), nullable=False),
        sa.Column("source_kind", sa.String(length=20), nullable=False),
        sa.Column("stack_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "status", sa.String(length=20), server_default="OPEN", nullable=False
        ),
        sa.Column(
            "risk_score", sa.Numeric(precision=4, scale=2), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "risk_factors",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "occurrence_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "suppressed_occurrence_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "environments_seen",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column(
            "route_templates",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "regressed", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("triage_note", sa.String(length=2000), server_default="", nullable=False),
        sa.Column("triaged_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('OPEN', 'CONFIRMED', 'REMEDIATED', 'FALSE_POSITIVE', 'ACCEPTED_RISK')",
            name="ck_findings_findings_status",
        ),
        sa.CheckConstraint(
            "severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_findings_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('SUSPECTED', 'CONFIRMED', 'EXPLOITED')",
            name="ck_findings_findings_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_findings_application_id_applications",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_findings_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["triaged_by"], ["users.id"], name="fk_findings_triaged_by_users", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        # The constraint that makes ingest idempotent: replaying the same event stream
        # converges on the same rows rather than multiplying them (ADR-0009).
        sa.UniqueConstraint(
            "organization_id", "identity_hash", name="uq_findings_organization_id_identity_hash"
        ),
    )
    op.create_index(
        "ix_findings_organization_id_status_risk_score",
        "findings",
        ["organization_id", "status", sa.text("risk_score DESC")],
    )
    op.create_index(
        "ix_findings_organization_id_application_id",
        "findings",
        ["organization_id", "application_id"],
    )
    op.create_index(
        "ix_findings_organization_id_last_seen_at",
        "findings",
        ["organization_id", "last_seen_at"],
    )
    op.create_index(
        "ix_findings_accepted_until",
        "findings",
        ["accepted_until"],
        postgresql_where=sa.text("status = 'ACCEPTED_RISK'"),
    )

    op.create_table(
        "finding_occurrences",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment", sa.String(length=20), server_default="", nullable=False),
        sa.Column("trace_id", sa.String(length=64), server_default="", nullable=False),
        sa.Column("request_method", sa.String(length=10), server_default="", nullable=False),
        sa.Column("request_path", sa.String(length=500), server_default="", nullable=False),
        sa.Column("route_template", sa.String(length=500), server_default="", nullable=False),
        sa.Column("sink_argument", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "tainted_ranges",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "stack_frames",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("remote_address", postgresql.INET(), nullable=True),
        sa.Column(
            "attack_detected", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_finding_occurrences_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_finding_occurrences_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_occurrences"),
    )
    op.create_index(
        "ix_finding_occurrences_finding_id_observed_at",
        "finding_occurrences",
        ["finding_id", sa.text("observed_at DESC")],
    )
    op.create_index(
        "ix_finding_occurrences_organization_id", "finding_occurrences", ["organization_id"]
    )

    op.create_table(
        "finding_comments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("author_label", sa.String(length=200), server_default="", nullable=False),
        sa.Column("body", sa.String(length=4000), nullable=False),
        sa.Column("status_from", sa.String(length=20), nullable=True),
        sa.Column("status_to", sa.String(length=20), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name="fk_finding_comments_author_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_finding_comments_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_finding_comments_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_comments"),
    )
    op.create_index(
        "ix_finding_comments_finding_id_created_at",
        "finding_comments",
        ["finding_id", "created_at"],
    )
    op.create_index(
        "ix_finding_comments_organization_id", "finding_comments", ["organization_id"]
    )

    _apply_row_level_security()
    _make_comments_append_only()


def _apply_row_level_security() -> None:
    """The same policy 0001 applies, extended to the new tables.

    Repeated verbatim rather than imported, because a migration must describe the schema as
    it was at the time it ran. If a later change alters the predicate, this migration should
    still reproduce the database it originally produced.
    """
    predicate = (
        "organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        " OR current_setting('app.rls_bypass', true) = 'on'"
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE, or the table owner — usually the application role — bypasses the policy and
        # the whole control is decorative.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def _make_comments_append_only() -> None:
    """Reject UPDATE and DELETE on triage comments at the database level.

    Someone dismissing a live vulnerability leaves a written reason. After an incident, that
    reason is exactly what an investigation reads — and exactly what someone would most want
    to change. A trigger rather than a grant, for the same reason as the audit chain: grants
    are per-role, and a deployment running migrations and the application as one role would
    otherwise have no protection at all.
    """
    op.execute("""
        CREATE OR REPLACE FUNCTION finding_comments_reject_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'finding_comments is append-only (%)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute("""
        CREATE TRIGGER finding_comments_append_only
        BEFORE UPDATE OR DELETE ON finding_comments
        FOR EACH ROW EXECUTE FUNCTION finding_comments_reject_mutation();
        """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS finding_comments_append_only ON finding_comments")
    op.execute("DROP FUNCTION IF EXISTS finding_comments_reject_mutation()")
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_table("finding_comments")
    op.drop_table("finding_occurrences")
    op.drop_table("findings")
