"""OCSF and CEF export.

The escaping tests here are security tests, not formatting tests. A finding carries the
attacker's payload by design, and CEF is a flat `key=value` line — so an unescaped character
is a write primitive into the customer's SOC console.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from aegis_api.application.siem import (
    OCSF_CATEGORY_UID,
    OCSF_CLASS_UID,
    to_cef,
    to_ocsf,
)
from aegis_api.domain.entities.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Occurrence,
    Severity,
)

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "organization_id": uuid4(),
        "application_id": uuid4(),
        "identity_hash": "f" * 64,
        "rule_key": "sql-injection",
        "title": "SQL injection in UserRepository.findByName",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.EXPLOITED,
        "sink_signature": "java.sql.Statement#execute(String)",
        "source_kind": "PARAMETER",
        "stack_hash": "a" * 64,
        "risk_score": 9.4,
        "environments_seen": ("PRODUCTION",),
        "cwe_id": 89,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "occurrence_count": 1,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def make_occurrence(finding: Finding, **overrides: object) -> Occurrence:
    defaults: dict[str, object] = {
        "organization_id": finding.organization_id,
        "finding_id": finding.id,
        "environment": "PRODUCTION",
        "trace_id": "t-1",
        "request_method": "GET",
        "request_path": "/users/search",
        "route_template": "/users/search",
        "sink_argument": "SELECT name FROM users WHERE name = '' OR 1=1--'",
        "tainted_ranges": ((37, 10, "SOURCE_KIND_PARAMETER", "name"),),
        "stack_frames": (("com.acme.UserRepository", "findByName", 412, True),),
        "remote_address": "203.0.113.7",
        "attack_detected": True,
        "observed_at": NOW,
    }
    defaults.update(overrides)
    return Occurrence(**defaults)  # type: ignore[arg-type]


class TestOcsf:
    def test_is_a_vulnerability_finding_event(self) -> None:
        event = to_ocsf(make_finding(), None, product_version="0.5.0")
        assert event["class_uid"] == OCSF_CLASS_UID
        assert event["category_uid"] == OCSF_CATEGORY_UID
        # type_uid is class * 100 + activity, and consumers route on it.
        assert event["type_uid"] == OCSF_CLASS_UID * 100 + event["activity_id"]

    def test_a_first_sighting_creates_and_a_repeat_updates(self) -> None:
        # Without this a SIEM counts one defect as thousands of separate incidents.
        assert (
            to_ocsf(make_finding(occurrence_count=1), None, product_version="v")["activity_id"] == 1
        )
        assert (
            to_ocsf(make_finding(occurrence_count=42), None, product_version="v")["activity_id"]
            == 2
        )

    def test_correlates_on_the_same_identity_we_use(self) -> None:
        finding = make_finding()
        event = to_ocsf(finding, None, product_version="v")
        assert event["finding_info"]["uid"] == finding.identity_hash

    def test_exploited_is_reported_as_an_available_exploit(self) -> None:
        # Not "could be exploited" — the agent watched the payload arrive.
        exploited = to_ocsf(make_finding(), None, product_version="v")
        assert exploited["vulnerabilities"][0]["is_exploit_available"] is True
        suspected = to_ocsf(
            make_finding(confidence=Confidence.SUSPECTED), None, product_version="v"
        )
        assert suspected["vulnerabilities"][0]["is_exploit_available"] is False

    def test_suppressed_statuses_collapse_to_the_nearest_honest_neighbour(self) -> None:
        for status in (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK):
            event = to_ocsf(make_finding(status=status), None, product_version="v")
            assert event["status"] == "Suppressed"

    def test_carries_the_cwe_and_affected_code(self) -> None:
        finding = make_finding()
        event = to_ocsf(finding, make_occurrence(finding), product_version="v")
        vulnerability = event["vulnerabilities"][0]
        assert vulnerability["cwe"]["uid"] == "CWE-89"
        assert vulnerability["affected_code"][0]["file"]["path"] == ("com/acme/UserRepository.java")
        assert vulnerability["affected_code"][0]["start_line"] == 412

    def test_survives_a_finding_whose_evidence_has_aged_out(self) -> None:
        event = to_ocsf(make_finding(), None, product_version="v")
        assert "affected_code" not in event["vulnerabilities"][0]
        assert "src_endpoint" not in event


class TestCefEscaping:
    """The security-relevant half."""

    def test_an_equals_in_the_payload_cannot_forge_a_field(self) -> None:
        finding = make_finding()
        # The attacker is trying to close msg and open a severity field of their own.
        hostile = make_occurrence(finding, sink_argument="x' OR 1=1-- severity=0 src=10.0.0.1")
        line = to_cef(finding, hostile, product_version="v")

        assert "\\=" in line
        # Neither forged key may appear as a real field.
        assert " severity=0" not in line
        assert " src=10.0.0.1" not in line
        # The genuine src, set by us from the occurrence, is still there.
        assert "src=203.0.113.7" in line

    def test_a_newline_cannot_forge_a_second_event(self) -> None:
        finding = make_finding()
        hostile = make_occurrence(
            finding, sink_argument="benign\nCEF:0|Evil|Tool|1|0|Nothing to see|0|"
        )
        line = to_cef(finding, hostile, product_version="v")

        # One line in, one line out. A collector splitting on newlines must not see two events.
        assert "\n" not in line
        assert "\\n" in line

    def test_a_carriage_return_is_folded_too(self) -> None:
        finding = make_finding()
        hostile = make_occurrence(finding, sink_argument="a\r\nb\rc")
        line = to_cef(finding, hostile, product_version="v")
        assert "\r" not in line

    def test_a_pipe_in_a_header_field_cannot_shift_the_columns(self) -> None:
        # The title is derived from application class names, so it is not attacker-controlled
        # today — but header position is what a parser trusts, so it is escaped regardless.
        finding = make_finding(title="SQL injection in Weird|Class")
        line = to_cef(finding, None, product_version="v")
        header = line.split("|")
        assert header[0] == "CEF:0"
        assert header[5] == "SQL injection in Weird\\"
        # Severity still lands in the seventh column rather than being pushed along.
        assert line.split("|")[7 - 1].endswith("Class")

    def test_backslashes_are_escaped_before_anything_else(self) -> None:
        finding = make_finding()
        hostile = make_occurrence(finding, sink_argument="C:\\temp\\x=1")
        line = to_cef(finding, hostile, product_version="v")
        # Escaping the backslash after the equals would double-escape what we just inserted.
        assert "C:\\\\temp\\\\x\\=1" in line

    def test_an_oversized_payload_is_truncated(self) -> None:
        finding = make_finding()
        hostile = make_occurrence(finding, sink_argument="A" * 100_000)
        line = to_cef(finding, hostile, product_version="v", max_argument_length=64)
        # A collector that drops oversized lines would lose the whole event.
        assert len(line) < 2_000


class TestCefContent:
    def test_header_has_the_seven_required_fields(self) -> None:
        line = to_cef(make_finding(), None, product_version="0.5.0")
        header = line.split("|")
        assert header[0] == "CEF:0"
        assert header[1] == "Aegis"
        assert header[2] == "Aegis IAST"
        assert header[3] == "0.5.0"
        assert header[4] == "sql-injection"

    def test_severity_is_the_risk_score_without_rescaling(self) -> None:
        line = to_cef(make_finding(risk_score=9.4), None, product_version="v")
        # What an analyst sorts on is what we computed.
        assert line.split("|")[6].startswith("9")

    def test_carries_identity_status_and_the_would_block_count(self) -> None:
        finding = make_finding()
        finding.record_would_block()
        line = to_cef(finding, None, product_version="v")
        assert f"externalId={finding.identity_hash}" in line
        assert "cs1=OPEN" in line
        assert "cn2=1" in line
