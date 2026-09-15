"""Demo data seeder for local dashboard visualization.

Populates demo organization, owner account, application, agent, findings,
and taint occurrences into the control plane database.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from aegis_api.config import Settings, get_settings
from aegis_api.container import build_container
from aegis_api.domain.entities.findings import Confidence, Finding, FindingStatus, Occurrence, Severity
from aegis_api.domain.entities.inventory import Application, Criticality, EnvironmentKind, Language, ProtectionMode
from aegis_api.domain.entities.organization import Organization
from aegis_api.infrastructure.db.models import Base


async def seed_demo_data() -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://aegis:aegis_local_dev@localhost:5433/aegis",
        enforce_row_level_security=False,
    )
    container = build_container(settings)

    # Create tables
    async with container.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    org_id = uuid4()
    app_id = uuid4()
    user_id = uuid4()
    now = datetime.now(UTC)

    async with container.unit_of_work() as uow:
        # 1. Create Organization
        org = Organization(
            id=org_id,
            name="Aegis Demo Corp",
            slug="aegis-demo",
            created_at=now,
        )
        await uow.organizations.add(org)
        await uow.bind_tenant(org_id)

        # 2. Create Application
        app = Application(
            id=app_id,
            organization_id=org_id,
            name="Payment Service Gateway",
            slug="payment-service",
            language=Language.PYTHON,
            criticality=Criticality.CRITICAL,
            internet_facing=True,
            created_at=now,
        )
        await uow.applications.add(app)

        # 3. Create Finding 1: SQL Injection
        f1 = Finding(
            id=uuid4(),
            organization_id=org_id,
            application_id=app_id,
            identity_hash="a" * 64,
            rule_key="sql-injection",
            title="SQL Injection in UserRepository.findByName",
            severity=Severity.CRITICAL,
            confidence=Confidence.EXPLOITED,
            status=FindingStatus.OPEN,
            risk_score=9.5,
            sink_signature="sqlite3.Cursor.execute",
            source_kind="PARAMETER",
            stack_hash="b" * 64,
            cwe_id=89,
            created_at=now,
            updated_at=now,
        )
        await uow.findings.add(f1)

        # Occurrence for Finding 1
        occ1 = Occurrence(
            id=uuid4(),
            organization_id=org_id,
            finding_id=f1.id,
            environment="PRODUCTION",
            trace_id="py-trace-7254ce20bd3d",
            request_method="GET",
            request_path="/api/users/search",
            route_template="/api/users/search",
            sink_argument="SELECT id, username, role FROM users WHERE username = 'admin' OR '1'='1'",
            tainted_ranges=((46, 17, "SOURCE_KIND_PARAMETER", "name"),),
            stack_frames=(
                ("tests.vulnerable_app.app", "search_users", 42, True),
                ("sqlite3.Cursor", "execute", 0, False),
            ),
            remote_address="203.0.113.7",
            attack_detected=True,
            observed_at=now,
        )
        await uow.findings.add_occurrence(occ1)

        # 4. Create Finding 2: Command Injection
        f2 = Finding(
            id=uuid4(),
            organization_id=org_id,
            application_id=app_id,
            identity_hash="c" * 64,
            rule_key="command-injection",
            title="OS Command Injection in NetworkDiagnostics.pingHost",
            severity=Severity.CRITICAL,
            confidence=Confidence.EXPLOITED,
            status=FindingStatus.OPEN,
            risk_score=9.8,
            sink_signature="subprocess.Popen",
            source_kind="PARAMETER",
            stack_hash="d" * 64,
            cwe_id=78,
            created_at=now,
            updated_at=now,
        )
        await uow.findings.add(f2)

        # Occurrence for Finding 2
        occ2 = Occurrence(
            id=uuid4(),
            organization_id=org_id,
            finding_id=f2.id,
            environment="PRODUCTION",
            trace_id="py-trace-5c77e70bb729",
            request_method="GET",
            request_path="/api/system/ping",
            route_template="/api/system/ping",
            sink_argument="ping -c 1 127.0.0.1; whoami",
            tainted_ranges=((10, 19, "SOURCE_KIND_PARAMETER", "host"),),
            stack_frames=(
                ("tests.vulnerable_app.app", "ping_host", 75, True),
                ("subprocess", "Popen", 0, False),
            ),
            remote_address="203.0.113.7",
            attack_detected=True,
            observed_at=now,
        )
        await uow.findings.add_occurrence(occ2)

        await uow.commit()

    print("[SUCCESS] Demo findings and occurrences successfully seeded into control plane database!")
    await container.aclose()


if __name__ == "__main__":
    asyncio.run(seed_demo_data())
