"""End-to-end smoke check against an in-process app instance."""
import asyncio, sys, httpx
from aegis_api.main import create_app

async def main() -> int:
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    failures = []
    def check(label, actual, expected):
        ok = actual == expected
        print(f"{'PASS' if ok else 'FAIL'}  {label}: {actual} (expected {expected})")
        if not ok: failures.append(label)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            import uuid
            suffix = uuid.uuid4().hex[:8]
            r = await c.post("/api/v1/auth/register", json={
                "organization_name": f"Smoke {suffix}",
                "email": f"smoke-{suffix}@example.com",
                "password": "correct-horse-battery-77",
                "full_name": "Smoke Tester"})
            check("register", r.status_code, 201)
            if r.status_code != 201:
                print(r.text); return 1
            h = {"Authorization": f"Bearer {r.json()['tokens']['access_token']}"}

            check("me", (await c.get("/api/v1/auth/me", headers=h)).status_code, 200)
            r = await c.post("/api/v1/applications", headers=h, json={
                "name": "Payments API", "language": "JAVA", "criticality": "CRITICAL",
                "tags": ["pci","payments"], "environments":[{"kind":"PRODUCTION","internet_facing":True}]})
            check("create application", r.status_code, 201)
            env_id = r.json()["environments"][0]["id"]

            r = await c.put(f"/api/v1/environments/{env_id}/protection", headers=h, json={"mode":"BLOCK"})
            # A TRIAL licence does not include blocking, so entitlement is checked first.
            check("block rejected on trial licence", r.status_code, 402)

            r = await c.post("/api/v1/api-keys", headers=h, json={
                "name":"ci","permissions":["agent:write","app:read"],"expires_in_days":30})
            check("issue api key", r.status_code, 201)
            key = r.json()["secret"]

            r = await c.post("/api/v1/agents/register", headers={"Authorization": f"Bearer {key}"}, json={
                "application_name":"Payments API","environment":"PRODUCTION","language":"JAVA",
                "fingerprint":f"fp-{suffix}-abc123","hostname":"pay-01","agent_version":"0.4.0",
                "runtime_version":"21.0.2"})
            check("agent register", r.status_code, 201)
            ah = {"Authorization": f"Bearer {r.json()['agent_token']}"}

            r = await c.post("/api/v1/agents/heartbeat", headers=ah, json={
                "cpu_overhead_pct":2.1,"memory_mb":98,"events_sent":10})
            check("heartbeat", r.status_code, 200)
            check("heartbeat status", r.json()["status"], "ONLINE")
            check("agent config", (await c.get("/api/v1/agents/config", headers=ah)).status_code, 200)
            check("agent token on user route", (await c.get("/api/v1/auth/me", headers=ah)).status_code, 401)
            check("api key on agent route", (await c.get("/api/v1/agents/config",
                  headers={"Authorization": f"Bearer {key}"})).status_code, 401)

            r = await c.get("/api/v1/audit-events", headers=h)
            check("audit list", r.status_code, 200)
            check("audit chain intact", (await c.get("/api/v1/audit-events/verify", headers=h)).json()["intact"], True)

            check("refresh via cookie", (await c.post("/api/v1/auth/refresh", json={})).status_code, 200)
            check("stale refresh reuse", (await c.post("/api/v1/auth/refresh", json={})).status_code, 200)
            check("healthz", (await c.get("/healthz")).status_code, 200)
            check("readyz", (await c.get("/readyz")).status_code, 200)

    print()
    print("ALL PASSED" if not failures else f"{len(failures)} FAILED: {failures}")
    return 0 if not failures else 1

sys.exit(asyncio.run(main()))
