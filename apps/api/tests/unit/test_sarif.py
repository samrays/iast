"""SARIF export.

Tested as a document a consumer has to accept, not as a dict we happen to build: the structural
requirements GitHub code scanning actually enforces, and the two mappings that are easy to get
subtly wrong — fingerprints and suppressions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from aegis_api.application.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    _artifact_uri,
    build_sarif,
)
from aegis_api.domain.entities.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Occurrence,
    Severity,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)


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
        "route_templates": ("/users/search",),
        "environments_seen": ("PRODUCTION",),
        "cwe_id": 89,
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
        "stack_frames": (
            ("java.sql.Statement", "execute", 0, False),
            ("com.acme.UserRepository", "findByName", 412, True),
            ("com.acme.SearchController", "search", 88, True),
        ),
        "attack_detected": True,
        "observed_at": NOW,
    }
    defaults.update(overrides)
    return Occurrence(**defaults)  # type: ignore[arg-type]


def export(*pairs: tuple[Finding, Occurrence | None]) -> dict:
    return build_sarif(list(pairs), tool_version="0.5.0", tool_uri="https://example.invalid")


class TestDocumentShape:
    def test_declares_the_version_a_consumer_checks_first(self) -> None:
        document = export((make_finding(), None))
        assert document["version"] == SARIF_VERSION
        assert document["$schema"] == SARIF_SCHEMA
        assert len(document["runs"]) == 1

    def test_names_the_tool_and_its_rules(self) -> None:
        document = export((make_finding(), None))
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Aegis IAST"
        assert driver["version"] == "0.5.0"
        assert [rule["id"] for rule in driver["rules"]] == ["sql-injection"]

    def test_every_result_indexes_a_rule_that_exists(self) -> None:
        # A dangling ruleIndex is the classic way a SARIF file is accepted and then renders
        # with no rule metadata at all.
        document = export(
            (make_finding(), None),
            (make_finding(rule_key="command-injection", identity_hash="e" * 64), None),
            (make_finding(identity_hash="d" * 64), None),
        )
        run = document["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 2, "the repeated rule must be declared once"
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_tags_the_cwe_so_a_security_team_can_filter(self) -> None:
        document = export((make_finding(), None))
        tags = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert "external/cwe/cwe-89" in tags
        assert "security" in tags


class TestSeverityMapping:
    def test_critical_and_high_are_errors(self) -> None:
        for severity in (Severity.CRITICAL, Severity.HIGH):
            document = export((make_finding(severity=severity), None))
            assert document["runs"][0]["results"][0]["level"] == "error"

    def test_low_severity_is_downgraded_rather_than_dropped(self) -> None:
        # Silently discarding low findings on export would misrepresent the scan.
        document = export((make_finding(severity=Severity.LOW), None))
        assert document["runs"][0]["results"][0]["level"] == "note"

    def test_security_severity_is_a_string_on_the_github_scale(self) -> None:
        document = export((make_finding(risk_score=9.4), None))
        # GitHub reads this as a string and sorts on it; a float here is silently ignored.
        value = document["runs"][0]["results"][0]["properties"]["security-severity"]
        assert value == "9.4"
        assert isinstance(value, str)

    def test_precision_follows_confidence(self) -> None:
        document = export((make_finding(confidence=Confidence.SUSPECTED), None))
        assert document["runs"][0]["results"][0]["properties"]["precision"] == "medium"


class TestFingerprints:
    def test_carries_our_deterministic_identity(self) -> None:
        finding = make_finding()
        document = export((finding, make_occurrence(finding)))
        fingerprints = document["runs"][0]["results"][0]["partialFingerprints"]
        assert fingerprints["aegisIdentityHash/v1"] == finding.identity_hash

    def test_the_fingerprint_does_not_depend_on_the_line(self) -> None:
        # The property that matters: a reformat moves every line, and the consumer must still
        # see one finding with its triage history rather than a close and a reopen.
        finding = make_finding()
        before = export((finding, make_occurrence(finding)))
        after = export(
            (
                finding,
                make_occurrence(
                    finding,
                    stack_frames=(("com.acme.UserRepository", "findByName", 999, True),),
                ),
            )
        )
        assert (
            before["runs"][0]["results"][0]["partialFingerprints"]
            == after["runs"][0]["results"][0]["partialFingerprints"]
        )
        # ...even though the reported location did move.
        assert (
            before["runs"][0]["results"][0]["locations"]
            != after["runs"][0]["results"][0]["locations"]
        )


class TestLocations:
    def test_reconstructs_a_source_path_from_the_application_frame(self) -> None:
        finding = make_finding()
        document = export((finding, make_occurrence(finding)))
        location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        # The innermost *application* frame, not the JDK frame above it.
        assert location["artifactLocation"]["uri"] == "com/acme/UserRepository.java"
        assert location["region"]["startLine"] == 412

    def test_nested_classes_resolve_to_their_outer_file(self) -> None:
        assert _artifact_uri("com.acme.Outer$Inner$1") == "com/acme/Outer.java"

    def test_a_finding_with_no_evidence_still_exports(self) -> None:
        # Evidence ages out of retention; the export must degrade rather than fail.
        document = export((make_finding(), None))
        assert document["runs"][0]["results"][0]["locations"] == []

    def test_omits_the_region_when_no_line_is_known(self) -> None:
        finding = make_finding()
        occurrence = make_occurrence(
            finding, stack_frames=(("com.acme.UserRepository", "findByName", 0, True),)
        )
        physical = export((finding, occurrence))["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]
        # A fabricated line is worse than none: it points somewhere specific and wrong.
        assert "region" not in physical


class TestSuppressions:
    def test_an_open_finding_is_not_suppressed(self) -> None:
        document = export((make_finding(), None))
        assert "suppressions" not in document["runs"][0]["results"][0]

    def test_a_dismissal_here_is_a_dismissal_there(self) -> None:
        finding = make_finding()
        finding.transition(
            FindingStatus.FALSE_POSITIVE,
            actor_id=uuid4(),
            now=NOW,
            note="Test fixture, not reachable in production.",
        )
        suppression = export((finding, None))["runs"][0]["results"][0]["suppressions"][0]
        # Without this the finding reappears in the next pull request and somebody re-triages
        # a decision that was already made.
        assert suppression["justification"] == "Test fixture, not reachable in production."
        assert suppression["properties"]["aegisStatus"] == "FALSE_POSITIVE"

    def test_an_accepted_risk_carries_its_reason(self) -> None:
        finding = make_finding()
        finding.transition(
            FindingStatus.ACCEPTED_RISK,
            actor_id=uuid4(),
            now=NOW,
            note="Mitigated by the edge WAF rule.",
        )
        suppression = export((finding, None))["runs"][0]["results"][0]["suppressions"][0]
        assert "WAF" in suppression["justification"]


class TestMessage:
    def test_answers_why_this_is_here_without_opening_the_console(self) -> None:
        finding = make_finding()
        text = export((finding, make_occurrence(finding)))["runs"][0]["results"][0]["message"][
            "text"
        ]
        assert "SQL injection" in text
        assert "java.sql.Statement#execute(String)" in text
        assert "/users/search" in text
        assert "PRODUCTION" in text
        assert "exploitation attempt" in text

    def test_reports_the_would_block_count_when_there_is_one(self) -> None:
        finding = make_finding()
        finding.record_would_block()
        properties = export((finding, None))["runs"][0]["results"][0]["properties"]
        assert properties["aegisWouldBlock"] == 1

    def test_an_empty_export_is_still_a_valid_document(self) -> None:
        document = export()
        assert document["runs"][0]["results"] == []
        assert document["runs"][0]["tool"]["driver"]["rules"] == []
