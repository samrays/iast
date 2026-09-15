"""Seeder script: Ingests all 10 OWASP Top 10 findings for aegis-demo-corp organization."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import sys
from pathlib import Path
from uuid import UUID, uuid4

repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root / "apps" / "api" / "src"))

from aegis_api.config import Settings
from aegis_api.container import build_container
from aegis_api.application.findings import ProcessRuntimeEvents
from aegis_api.domain.entities.organization import Organization
from aegis_api.domain.entities.inventory import (
    Agent,
    AgentStatus,
    Application,
    ApplicationEnvironment,
    Criticality,
    EnvironmentKind,
    Language,
    ProtectionMode,
)
from aegis_api.domain.value_objects import Slug
from aegis_api.infrastructure.db.models import Base


NOW_MS = int(datetime.now(UTC).timestamp() * 1000)

OWASP_FINDINGS = [
    {
        "rule_key": "sql-injection",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_EXPLOITED",
        "sink": "sqlite3.Cursor.execute",
        "sink_argument": "SELECT id, username, role FROM users WHERE username = 'admin' OR '1'='1'",
        "route": "/api/users/search",
        "cwe_id": 89,
        "method": "GET",
    },
    {
        "rule_key": "command-injection",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_EXPLOITED",
        "sink": "subprocess.Popen",
        "sink_argument": "ping -c 1 127.0.0.1; whoami",
        "route": "/api/system/ping",
        "cwe_id": 78,
        "method": "GET",
    },
    {
        "rule_key": "unsafe-deserialization",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "pickle.loads",
        "sink_argument": "cos\nsystem\n(S'id'\ntR.",
        "route": "/api/data/deserialize",
        "cwe_id": 502,
        "method": "POST",
    },
    {
        "rule_key": "xxe",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "xml.etree.ElementTree.fromstring",
        "sink_argument": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "route": "/api/xml/parse",
        "cwe_id": 611,
        "method": "POST",
    },
    {
        "rule_key": "path-traversal",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "builtins.open",
        "sink_argument": "../../../../etc/passwd",
        "route": "/api/files/read",
        "cwe_id": 22,
        "method": "GET",
    },
    {
        "rule_key": "reflected-xss",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "fastapi.responses.HTMLResponse",
        "sink_argument": "<div>Welcome, <script>alert(1)</script>!</div>",
        "route": "/api/render/html",
        "cwe_id": 79,
        "method": "GET",
    },
    {
        "rule_key": "ssrf",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "urllib.request.urlopen",
        "sink_argument": "http://169.254.169.254/latest/meta-data/",
        "route": "/api/fetch/url",
        "cwe_id": 918,
        "method": "GET",
    },
    {
        "rule_key": "open-redirect",
        "severity": "SEVERITY_MEDIUM",
        "confidence": "CONFIDENCE_MEDIUM",
        "sink": "fastapi.responses.RedirectResponse",
        "sink_argument": "http://example.com",
        "route": "/api/navigate/redirect",
        "cwe_id": 601,
        "method": "GET",
    },
    {
        "rule_key": "header-injection",
        "severity": "SEVERITY_MEDIUM",
        "confidence": "CONFIDENCE_MEDIUM",
        "sink": "fastapi.responses.Response.headers",
        "sink_argument": "val\r\nSet-Cookie: session=stolen",
        "route": "/api/headers/set",
        "cwe_id": 113,
        "method": "GET",
    },
    {
        "rule_key": "log-injection",
        "severity": "SEVERITY_MEDIUM",
        "confidence": "CONFIDENCE_MEDIUM",
        "sink": "logging.Logger.info",
        "sink_argument": "User logged in\nADMIN GRANTED",
        "route": "/api/system/log",
        "cwe_id": 117,
        "method": "GET",
    },
]


async def main() -> None:
    settings = Settings()
    container = build_container(settings)

    now = datetime.now(UTC)

    async with container.unit_of_work() as uow:
        # 1. Target aegis-demo-corp (owner@aegis.example organization)
        org = await uow.organizations.get_by_slug(Slug("aegis-demo-corp"))
        if not org:
            print("Organization aegis-demo-corp not found.")
            return

        org_id = org.id
        await uow.bind_tenant(org_id)

        # 2. Get or create application
        app_slug = Slug("owasp-top10-app")
        app = await uow.applications.get_by_slug(app_slug)
        if not app:
            app = Application(
                id=uuid4(),
                organization_id=org_id,
                name="OWASP Top 10 Test Application",
                slug=app_slug,
                language=Language.PYTHON,
                criticality=Criticality.CRITICAL,
                created_at=now,
            )
            await uow.applications.add(app)

        app_id = app.id

        # 3. Get or create environment
        envs = await uow.environments.list_for_application(app_id)
        if envs:
            env = envs[0]
        else:
            env = ApplicationEnvironment(
                id=uuid4(),
                organization_id=org_id,
                application_id=app_id,
                kind=EnvironmentKind.PRODUCTION,
                internet_facing=True,
                protection_mode=ProtectionMode.MONITOR,
                created_at=now,
            )
            await uow.environments.add(env)

        env_id = env.id

        # 4. Create new agent specifically for this application
        agent = Agent(
            id=uuid4(),
            organization_id=org_id,
            application_environment_id=env_id,
            fingerprint=uuid4().hex,
            hostname="owasp-test-host",
            agent_version="0.3.0",
            runtime_version="Python 3.12.0",
            language=Language.PYTHON,
            status=AgentStatus.ONLINE,
            created_at=now,
        )
        await uow.agents.add(agent)

        agent_id = str(agent.id)
        await uow.commit()

    # 5. Ingest OWASP Top 10 events
    pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)
    records = []

    for item in OWASP_FINDINGS:
        records.append({
            "organization_id": str(org_id),
            "agent_id": agent_id,
            "environment_id": str(env_id),
            "event_id": uuid4().hex,
            "type": "EVENT_TYPE_TAINT_HIT",
            "occurred_at_ms": NOW_MS,
            "monotonic_nanos": 1,
            "trace_id": f"py-trace-{uuid4().hex[:12]}",
            "replayed": False,
            "payload": {
                "rule_key": item["rule_key"],
                "severity": item["severity"],
                "confidence": item["confidence"],
                "sink_signature": item["sink"],
                "sink_argument": item["sink_argument"],
                "stack_fingerprint": uuid4().hex,
                "imprecise": False,
                "ranges": [
                    {
                        "start": 0,
                        "length": len(item["sink_argument"]),
                        "source": "SOURCE_KIND_PARAMETER",
                        "source_name": "input_param",
                    }
                ],
                "stack_trace": [
                    {"module": "vulnerable_app.app", "function": item["route"].replace("/api/", "").replace("/", "_"), "line": 42},
                    {"module": item["sink"].rsplit(".", 1)[0], "function": item["sink"].rsplit(".", 1)[-1], "line": 1},
                ],
                "http_context": {
                    "request_method": item["method"],
                    "request_path": item["route"],
                    "route_template": item["route"],
                    "remote_address": "127.0.0.1",
                    "user_agent": "Aegis-OWASP-TestHarness/1.0",
                },
            },
        })

    res = await pipeline.execute(records)
    print("\n======================================================================")
    print("      INGESTED OWASP TOP 10 FINDINGS INTO AEGIS-DEMO-CORP DATABASE")
    print("======================================================================")
    print(f"Findings Created  : {res.findings_created}")
    print(f"Findings Updated  : {res.findings_updated}")
    print(f"Occurrences Stored: {res.occurrences_stored}")
    print(f"Rejected Events   : {res.rejected}")


if __name__ == "__main__":
    asyncio.run(main())
