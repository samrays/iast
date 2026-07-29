"""Tenant isolation and immutability on the findings tables (threats T-03, T-11).

These run against a real PostgreSQL as the real ``NOSUPERUSER`` application role. Both
details matter: row-level security is entirely inert for a superuser, so a suite that
connected as one would pass while the control did nothing at all.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from tests.conftest import Tenant, create_application

from aegis_api.container import Container

pytestmark = [pytest.mark.integration, pytest.mark.security]

INSERT_FINDING = text("""
    INSERT INTO findings (
        id, organization_id, application_id, identity_hash, rule_key, title,
        severity, confidence, sink_signature, source_kind, stack_hash
    ) VALUES (
        :id, :organization_id, :application_id, :identity_hash, 'sql-injection',
        'SQL injection in UserRepository', 'CRITICAL', 'EXPLOITED',
        'java.sql.Statement#execute(String)', 'PARAMETER', :stack_hash
    )
""")


def unique_identity() -> str:
    """A fresh identity hash.

    The tenant fixtures are session-scoped, so tests share an organization. Hard-coding a
    hash here would make one test's row collide with another's and turn the idempotence
    constraint into a source of flakes.
    """
    return uuid4().hex * 2


async def _seed_finding(
    container: Container, organization_id: UUID, application_id: UUID, identity: str
) -> UUID:
    finding_id = uuid4()
    async with container.unit_of_work() as uow:
        await uow.bind_tenant(organization_id)
        await uow.session.execute(
            INSERT_FINDING,
            {
                "id": finding_id,
                "organization_id": organization_id,
                "application_id": application_id,
                "identity_hash": identity,
                "stack_hash": "b" * 64,
            },
        )
        await uow.commit()
    return finding_id


class TestTenantIsolation:
    async def test_one_tenant_cannot_read_another_tenants_findings(
        self, client, container: Container, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        application_id = UUID((await create_application(client, tenant, name="Payments"))["id"])
        identity = unique_identity()
        finding_id = await _seed_finding(
            container, UUID(tenant.organization_id), application_id, identity
        )

        seen = text("SELECT count(*) FROM findings WHERE id = :id")
        async with container.unit_of_work() as uow:
            await uow.bind_tenant(UUID(other_tenant.organization_id))
            result = await uow.session.execute(seen, {"id": finding_id})
            assert result.scalar_one() == 0

        async with container.unit_of_work() as uow:
            await uow.bind_tenant(UUID(tenant.organization_id))
            result = await uow.session.execute(seen, {"id": finding_id})
            assert result.scalar_one() == 1

    async def test_a_tenant_cannot_write_a_finding_into_another_tenant(
        self, client, container: Container, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        application_id = UUID((await create_application(client, tenant, name="Payments"))["id"])

        # The policy's WITH CHECK is what stops this. A USING-only policy would hide other
        # tenants' rows while still letting an attacker plant rows among them.
        with pytest.raises(DBAPIError):
            async with container.unit_of_work() as uow:
                await uow.bind_tenant(UUID(other_tenant.organization_id))
                await uow.session.execute(
                    INSERT_FINDING,
                    {
                        "id": uuid4(),
                        "organization_id": UUID(tenant.organization_id),
                        "application_id": application_id,
                        "identity_hash": unique_identity(),
                        "stack_hash": "d" * 64,
                    },
                )

    async def test_the_application_role_is_not_a_superuser(self, container: Container) -> None:
        # Stated as its own test because every isolation guarantee above silently evaporates
        # if this ever stops being true.
        async with container.unit_of_work() as uow:
            result = await uow.session.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            )
            assert result.scalar_one() is False


class TestIngestIdempotence:
    async def test_the_same_identity_cannot_be_inserted_twice(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        application_id = UUID((await create_application(client, tenant, name="Payments"))["id"])
        identity = unique_identity()
        await _seed_finding(container, UUID(tenant.organization_id), application_id, identity)

        # This constraint is what makes replay safe: the worker's at-least-once stream
        # converges on one row per defect instead of multiplying it on every restart.
        with pytest.raises(IntegrityError):
            await _seed_finding(container, UUID(tenant.organization_id), application_id, identity)

    async def test_two_tenants_may_share_an_identity_hash(
        self, client, container: Container, tenant: Tenant, other_tenant: Tenant
    ) -> None:
        # Identical code deployed by two customers produces the same hash. Scoping the
        # constraint per tenant is what stops one customer's finding blocking another's.
        first = UUID((await create_application(client, tenant, name="Payments"))["id"])
        second = UUID((await create_application(client, other_tenant, name="Payments"))["id"])

        shared = unique_identity()
        await _seed_finding(container, UUID(tenant.organization_id), first, shared)
        await _seed_finding(container, UUID(other_tenant.organization_id), second, shared)


class TestImmutability:
    async def _comment_id(
        self, container: Container, organization_id: UUID, finding_id: UUID
    ) -> UUID:
        comment_id = uuid4()
        async with container.unit_of_work() as uow:
            await uow.bind_tenant(organization_id)
            await uow.session.execute(
                text("""
                    INSERT INTO finding_comments (id, organization_id, finding_id, body)
                    VALUES (:id, :organization_id, :finding_id, :body)
                """),
                {
                    "id": comment_id,
                    "organization_id": organization_id,
                    "finding_id": finding_id,
                    "body": "Dismissed — believed to be a test fixture.",
                },
            )
            await uow.commit()
        return comment_id

    @pytest.mark.parametrize(
        "statement",
        [
            "UPDATE finding_comments SET body = 'nothing to see here' WHERE id = :id",
            "DELETE FROM finding_comments WHERE id = :id",
        ],
    )
    async def test_a_triage_comment_cannot_be_rewritten(
        self, client, container: Container, tenant: Tenant, statement: str
    ) -> None:
        organization_id = UUID(tenant.organization_id)
        application_id = UUID((await create_application(client, tenant, name="Payments"))["id"])
        finding_id = await _seed_finding(
            container, organization_id, application_id, unique_identity()
        )
        comment_id = await self._comment_id(container, organization_id, finding_id)

        # After an incident, the written reason someone dismissed a live vulnerability is
        # exactly what an investigation reads — and exactly what they would want to change.
        with pytest.raises(DBAPIError):
            async with container.unit_of_work() as uow:
                await uow.bind_tenant(organization_id)
                await uow.session.execute(text(statement), {"id": comment_id})

    async def test_evidence_cannot_be_rewritten(
        self, client, container: Container, tenant: Tenant
    ) -> None:
        organization_id = UUID(tenant.organization_id)
        application_id = UUID((await create_application(client, tenant, name="Payments"))["id"])
        finding_id = await _seed_finding(
            container, organization_id, application_id, unique_identity()
        )

        occurrence_id = uuid4()
        async with container.unit_of_work() as uow:
            await uow.bind_tenant(organization_id)
            await uow.session.execute(
                text("""
                    INSERT INTO finding_occurrences (
                        id, organization_id, finding_id, environment, trace_id, observed_at
                    ) VALUES (:id, :organization_id, :finding_id, 'PRODUCTION', 'trace-1', :now)
                """),
                {
                    "id": occurrence_id,
                    "organization_id": organization_id,
                    "finding_id": finding_id,
                    "now": datetime.now(UTC),
                },
            )
            await uow.commit()

        # Evidence of something that happened cannot retrospectively have happened
        # differently.
        with pytest.raises(DBAPIError):
            async with container.unit_of_work() as uow:
                await uow.bind_tenant(organization_id)
                await uow.session.execute(
                    text("UPDATE finding_occurrences SET sink_argument = 'x' WHERE id = :id"),
                    {"id": occurrence_id},
                )
