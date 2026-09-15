"""Seeder script: Ingests all Online Boutique test findings into the Aegis IAST Control Plane Database."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import sys
from pathlib import Path
from uuid import UUID, uuid4

# Ensure aegis_api is importable
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

BOUTIQUE_FINDINGS = [
    {
        "service": "recommendationservice",
        "rule_key": "sql-injection",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_EXPLOITED",
        "sink": "recommendation_svc.sqlite3.execute",
        "sink_argument": "SELECT id, name, category, price FROM products WHERE category = 'vintage' OR '1'='1'",
        "route": "/api/recommendations/raw_search",
        "cwe_id": 89,
        "method": "GET",
    },
    {
        "service": "recommendationservice",
        "rule_key": "path-traversal",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "recommendation_svc.open_asset",
        "sink_argument": "../../../../etc/passwd",
        "route": "/api/recommendations/catalog",
        "cwe_id": 22,
        "method": "GET",
    },
    {
        "service": "emailservice",
        "rule_key": "log-injection",
        "severity": "SEVERITY_MEDIUM",
        "confidence": "CONFIDENCE_MEDIUM",
        "sink": "email_svc.logging.info",
        "sink_argument": "Order ORD-9999 confirmation dispatched to attacker@evil.com. Customer Note: Delivered\nADMIN STATUS: ACCESS GRANTED",
        "route": "/api/email/send",
        "cwe_id": 117,
        "method": "POST",
    },
    {
        "service": "emailservice",
        "rule_key": "xxe",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "email_svc.xml.etree.ElementTree.fromstring",
        "sink_argument": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "route": "/api/email/template",
        "cwe_id": 611,
        "method": "POST",
    },
    {
        "service": "adservice",
        "rule_key": "reflected-xss",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "ad_svc.HTMLResponse",
        "sink_argument": "<div class='ad-banner'>Sponsored Deal for <span><script>alert('XSS')</script></span>: 20% OFF Vintage Items!</div>",
        "route": "/api/ads",
        "cwe_id": 79,
        "method": "GET",
    },
    {
        "service": "adservice",
        "rule_key": "command-injection",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_EXPLOITED",
        "sink": "ad_svc.subprocess.Popen",
        "sink_argument": "ping -c 1 127.0.0.1; whoami",
        "route": "/api/ads/telemetry",
        "cwe_id": 78,
        "method": "GET",
    },
    {
        "service": "currencyservice",
        "rule_key": "ssrf",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "currency_svc.urllib.urlopen",
        "sink_argument": "http://169.254.169.254/latest/meta-data/",
        "route": "/api/currency/rates",
        "cwe_id": 918,
        "method": "GET",
    },
    {
        "service": "currencyservice",
        "rule_key": "header-injection",
        "severity": "SEVERITY_MEDIUM",
        "confidence": "CONFIDENCE_MEDIUM",
        "sink": "currency_svc.Response.headers",
        "sink_argument": "val\r\nSet-Cookie: session=stolen",
        "route": "/api/currency/convert",
        "cwe_id": 113,
        "method": "GET",
    },
    {
        "service": "boutique_frontend",
        "rule_key": "open-redirect",
        "severity": "SEVERITY_MEDIUM",
        "confidence": "CONFIDENCE_MEDIUM",
        "sink": "boutique_frontend.RedirectResponse",
        "sink_argument": "http://attacker-controlled-phishing.com",
        "route": "/api/cart/checkout",
        "cwe_id": 601,
        "method": "GET",
    },
    {
        "service": "boutique_frontend",
        "rule_key": "unsafe-deserialization",
        "severity": "SEVERITY_CRITICAL",
        "confidence": "CONFIDENCE_HIGH",
        "sink": "boutique_frontend.pickle.loads",
        "sink_argument": "cos\nsystem\n(S'whoami'\ntR.",
        "route": "/api/cart/restore",
        "cwe_id": 502,
        "method": "POST",
    },
]


async def seed_for_org(container, org_slug_str: str, org_name_str: str):
    now = datetime.now(UTC)
    async with container.unit_of_work() as uow:
        org_slug = Slug(org_slug_str)
        org = await uow.organizations.get_by_slug(org_slug)
        if not org:
            org = Organization(
                id=uuid4(),
                name=org_name_str,
                slug=org_slug,
                created_at=now,
            )
            await uow.organizations.add(org)

        org_id = org.id
        await uow.bind_tenant(org_id)

        app_slug = Slug("google-online-boutique")
        app = await uow.applications.get_by_slug(app_slug)
        if not app:
            app = Application(
                id=uuid4(),
                organization_id=org_id,
                name="Google Online Boutique Microservices",
                slug=app_slug,
                language=Language.PYTHON,
                criticality=Criticality.CRITICAL,
                created_at=now,
            )
            await uow.applications.add(app)

        app_id = app.id

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

        agents, _ = await uow.agents.list_all(limit=10, cursor=None)
        if agents:
            agent = agents[0]
        else:
            agent = Agent(
                id=uuid4(),
                organization_id=org_id,
                application_environment_id=env_id,
                fingerprint=uuid4().hex,
                hostname="online-boutique-cluster-host",
                agent_version="0.3.0",
                runtime_version="Python 3.12.0",
                language=Language.PYTHON,
                status=AgentStatus.ONLINE,
                created_at=now,
            )
            await uow.agents.add(agent)

        agent_id = str(agent.id)
        await uow.commit()

    pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)
    records = []

    for item in BOUTIQUE_FINDINGS:
        records.append({
            "organization_id": str(org_id),
            "agent_id": agent_id,
            "environment_id": str(env_id),
            "event_id": uuid4().hex,
            "type": "EVENT_TYPE_TAINT_HIT",
            "occurred_at_ms": NOW_MS,
            "monotonic_nanos": 1,
            "trace_id": f"boutique-trace-{uuid4().hex[:12]}",
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
                    {"module": f"online_boutique.{item['service']}", "function": item["route"].replace("/api/", "").replace("/", "_"), "line": 42},
                    {"module": item["sink"].rsplit(".", 1)[0], "function": item["sink"].rsplit(".", 1)[-1], "line": 1},
                ],
                "http_context": {
                    "request_method": item["method"],
                    "request_path": item["route"],
                    "route_template": item["route"],
                    "remote_address": "127.0.0.1",
                    "user_agent": "Google-Online-Boutique-TestHarness/1.0",
                },
            },
        })

    res = await pipeline.execute(records)
    print(f"[{org_name_str}] Findings Created: {res.findings_created}, Stored: {res.occurrences_stored}")


async def main() -> None:
    settings = Settings()
    container = build_container(settings)

    async with container.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await seed_for_org(container, "aegis-security", "Aegis Security")
    await seed_for_org(container, "aegis-demo-corp", "Aegis Demo Corp")


if __name__ == "__main__":
    asyncio.run(main())
