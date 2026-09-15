from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import run_vulnerable_demo as demo


class FakeClient:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self.pages = iter(pages)

    def findings(self, token: str) -> dict[str, object]:
        return next(self.pages)


def page(count: int, application_id: str = "app-1") -> dict[str, object]:
    return {
        "items": [
            {
                "id": "finding-1",
                "application_id": application_id,
                "rule_key": "sql-injection",
                "occurrence_count": count,
            }
        ]
    }


class VulnerableDemoTest(unittest.TestCase):
    def test_occurrence_count_is_scoped_to_the_demo_application(self) -> None:
        findings = {
            "items": [
                {"application_id": "other", "occurrence_count": 99},
                {"application_id": "app-1", "occurrence_count": 3},
            ]
        }
        self.assertEqual(demo.occurrence_count(findings, "app-1"), 3)

    def test_wait_requires_a_new_durable_occurrence(self) -> None:
        client = FakeClient([page(4), page(5)])
        with patch.object(demo.time, "monotonic", side_effect=[0.0, 0.0, 0.0]):
            finding = demo.wait_for_import(
                client,
                "user-token",
                "app-1",
                4,
                timeout_seconds=1,
                sleep=lambda _: None,
            )
        self.assertEqual(finding["occurrence_count"], 5)

    def test_wait_fails_instead_of_claiming_an_unimported_finding(self) -> None:
        client = FakeClient([page(4)])
        with (
            patch.object(demo.time, "monotonic", side_effect=[0.0, 0.0, 2.0]),
            self.assertRaisesRegex(demo.DemoError, "no new control-plane occurrence"),
        ):
            demo.wait_for_import(
                client,
                "user-token",
                "app-1",
                4,
                timeout_seconds=1,
                sleep=lambda _: None,
            )

    def test_agent_credential_is_not_put_on_the_java_command_line(self) -> None:
        command = demo.java_command(
            "java", Path("agent.jar"), Path("test-classes"), Path("missing-libraries")
        )
        self.assertNotIn("api_key", " ".join(command).lower())
        self.assertEqual(command[-1], "com.example.app.VulnerableApp")
        self.assertEqual(command[2], "-cp")
        self.assertEqual(
            command[3].split(os.pathsep)[:2], ["test-classes", "agent.jar"]
        )

    def test_agent_credential_and_recovery_spool_are_environment_only(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            environment = demo.agent_environment("http://gateway:8081", "agent-secret")
        self.assertEqual(environment["AEGIS_API_KEY"], "agent-secret")
        self.assertEqual(environment["AEGIS_ENDPOINT"], "http://gateway:8081")
        self.assertTrue(
            environment["AEGIS_SPOOL_DIR"].endswith("vulnerable-demo-agent-spool")
        )


if __name__ == "__main__":
    unittest.main()
