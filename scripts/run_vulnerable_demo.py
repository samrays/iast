"""Run the Java vulnerability demo and require a control-plane finding.

This is intentionally stricter than the agent's file-transport integration test: success means
the gateway accepted the event, the worker stored it, and the authenticated findings API can read
the resulting record. A missing gateway or worker is a failed demo, never a silent local capture.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AGENT_PROJECT = ROOT / "agents" / "runtime" / "java-agent"
APPLICATION_NAME = "Vulnerable Demo App"


class DemoError(RuntimeError):
    """A user-actionable failure in the end-to-end demo."""


class ControlPlaneClient:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str = "",
        body: dict[str, Any] | None = None,
    ) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DemoError(
                f"{method} {path} returned HTTP {exc.code}: {detail}"
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise DemoError(f"Could not reach {self.base_url}{path}: {exc}") from exc
        return json.loads(payload) if payload else None

    def ready(self) -> None:
        readiness = self.request("GET", "/readyz")
        if readiness.get("status") != "ready":
            raise DemoError(f"Control plane is not ready: {readiness}")

    def login(self, email: str, password: str, organization: str) -> str:
        session = self.request(
            "POST",
            "/api/v1/auth/login",
            body={
                "email": email,
                "password": password,
                "organization_slug": organization,
            },
        )
        return str(session["access_token"])

    def ensure_application(self, token: str) -> dict[str, Any]:
        page = self.request("GET", "/api/v1/applications?limit=200", token=token)
        application = next(
            (item for item in page["items"] if item["name"] == APPLICATION_NAME), None
        )
        if application is None:
            return self.request(
                "POST",
                "/api/v1/applications",
                token=token,
                body={
                    "name": APPLICATION_NAME,
                    "language": "JAVA",
                    "criticality": "HIGH",
                    "tags": ["demo", "iast"],
                    "description": (
                        "Deliberately vulnerable local application used to verify the complete "
                        "Aegis ingest pipeline."
                    ),
                    "environments": [{"kind": "DEVELOPMENT", "internet_facing": False}],
                },
            )

        if not any(env["kind"] == "DEVELOPMENT" for env in application["environments"]):
            environment = self.request(
                "POST",
                f"/api/v1/applications/{application['id']}/environments",
                token=token,
                body={"kind": "DEVELOPMENT", "internet_facing": False},
            )
            application["environments"].append(environment)
        return application

    def register_agent(self, token: str) -> tuple[str, str, str]:
        issued = self.request(
            "POST",
            "/api/v1/api-keys",
            token=token,
            body={
                "name": "vulnerable-demo-registration",
                "permissions": ["agent:write", "app:read"],
                "expires_in_days": 1,
            },
        )
        key_id = str(issued["api_key"]["id"])
        try:
            registration = self.request(
                "POST",
                "/api/v1/agents/register",
                token=str(issued["secret"]),
                body={
                    "application_name": APPLICATION_NAME,
                    "environment": "DEVELOPMENT",
                    "language": "JAVA",
                    "fingerprint": f"vulnerable-demo-{os.urandom(16).hex()}",
                    "hostname": socket.gethostname(),
                    "agent_version": "0.4.0",
                    "runtime_version": "21",
                },
            )
            return (
                str(registration["agent_token"]),
                str(registration["agent"]["id"]),
                key_id,
            )
        except Exception:
            self.revoke_api_key(token, key_id)
            raise

    def revoke_api_key(self, token: str, key_id: str) -> None:
        self.request("DELETE", f"/api/v1/api-keys/{key_id}", token=token)

    def findings(self, token: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"limit": 200, "rule_key": "sql-injection"})
        return self.request("GET", f"/api/v1/findings?{query}", token=token)


def occurrence_count(page: dict[str, Any], application_id: str) -> int:
    """Return the highest SQL-injection occurrence count for this application."""
    return max(
        (
            int(item["occurrence_count"])
            for item in page["items"]
            if item["application_id"] == application_id
        ),
        default=0,
    )


def wait_for_import(
    client: ControlPlaneClient,
    token: str,
    application_id: str,
    previous_count: int,
    *,
    timeout_seconds: float = 30.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Wait until the worker has durably folded this run's event into a finding."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        page = client.findings(token)
        candidates = [
            item
            for item in page["items"]
            if item["application_id"] == application_id
            and int(item["occurrence_count"]) > previous_count
        ]
        if candidates:
            return max(candidates, key=lambda item: int(item["occurrence_count"]))
        sleep(1.0)
    raise DemoError(
        "The agent ran, but no new control-plane occurrence appeared. "
        "Confirm the ingest gateway and worker are running against the same event stream."
    )


def java_command(
    java: str, agent_jar: Path, test_classes: Path, libraries: Path
) -> list[str]:
    classpath = os.pathsep.join(
        [
            str(test_classes),
            str(agent_jar),
            *(str(path) for path in sorted(libraries.glob("*.jar"))),
        ]
    )
    return [
        java,
        f"-javaagent:{agent_jar}",
        "-cp",
        classpath,
        "com.example.app.VulnerableApp",
    ]


def agent_environment(gateway: str, agent_token: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "AEGIS_ENDPOINT": gateway,
            # Keep the short-lived credential out of the process command line.
            "AEGIS_API_KEY": agent_token,
            "AEGIS_APPLICATION_NAME": APPLICATION_NAME,
            "AEGIS_ENVIRONMENT": "DEVELOPMENT",
            "AEGIS_APPLICATION_PACKAGES": "com.example.app",
            "AEGIS_CAPTURE_REQUEST_BODY": "FULL",
            # A gateway restart after readiness must delay the finding, not lose it. The
            # next demo run renews the credential and replays this shared local spool.
            "AEGIS_SPOOL_DIR": str(
                ROOT / ".local-data" / "vulnerable-demo-agent-spool"
            ),
        }
    )
    return environment


def find_java(explicit: str) -> str:
    if explicit:
        return explicit
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = (
            Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        )
        if candidate.is_file():
            return str(candidate)
    java = shutil.which("java")
    if java:
        return java
    raise DemoError("Java was not found. Set JAVA_HOME or pass --java.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8080")
    parser.add_argument("--gateway", default="http://127.0.0.1:8081")
    parser.add_argument(
        "--email", default=os.environ.get("AEGIS_DEMO_EMAIL", "owner@aegis.example")
    )
    parser.add_argument(
        "--organization",
        default=os.environ.get("AEGIS_DEMO_ORGANIZATION", "aegis-demo"),
    )
    parser.add_argument("--java", default="")
    parser.add_argument(
        "--agent-jar", type=Path, default=AGENT_PROJECT / "target" / "aegis-agent.jar"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = os.environ.get("AEGIS_DEMO_PASSWORD")
    if not password and sys.stdin.isatty():
        password = getpass.getpass("Aegis dashboard password: ")
    if not password:
        raise DemoError(
            "Set AEGIS_DEMO_PASSWORD or run interactively to enter it securely."
        )

    client = ControlPlaneClient(args.api)
    client.ready()
    # Readiness is deliberately checked separately: the API being healthy says nothing about
    # whether the agent-facing gateway is available.
    ControlPlaneClient(args.gateway).ready()
    user_token = client.login(args.email, password, args.organization)
    application = client.ensure_application(user_token)
    application_id = str(application["id"])
    previous_count = occurrence_count(client.findings(user_token), application_id)

    agent_token, agent_id, key_id = client.register_agent(user_token)
    try:
        client.revoke_api_key(user_token, key_id)
        key_id = ""

        agent_jar = args.agent_jar.resolve()
        test_classes = AGENT_PROJECT / "target" / "test-classes"
        libraries = AGENT_PROJECT / "target" / "it-libs"
        if (
            not agent_jar.is_file()
            or not test_classes.is_dir()
            or not libraries.is_dir()
        ):
            raise DemoError(
                "The Java demo is not built. Run `mvn verify` in "
                "agents/runtime/java-agent first."
            )

        result = subprocess.run(
            java_command(find_java(args.java), agent_jar, test_classes, libraries),
            cwd=AGENT_PROJECT,
            env=agent_environment(args.gateway, agent_token),
            text=True,
            capture_output=True,
            check=False,
        )
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            raise DemoError(
                f"The vulnerable application exited with status {result.returncode}."
            )
        required = ("UNSAFE_ROWS=3", "SAFE_ROWS=0", "FINDINGS=1", "HOOK_FAILURES=0")
        missing = [marker for marker in required if marker not in result.stdout]
        if missing:
            raise DemoError(
                f"The vulnerable application omitted expected proof: {missing}"
            )

        finding = wait_for_import(client, user_token, application_id, previous_count)
        print(
            json.dumps(
                {
                    "application_id": application_id,
                    "agent_id": agent_id,
                    "finding_id": finding["id"],
                    "rule_key": finding["rule_key"],
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "status": finding["status"],
                    "occurrence_count": finding["occurrence_count"],
                },
                indent=2,
            )
        )
        return 0
    finally:
        if key_id:
            client.revoke_api_key(user_token, key_id)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
