"""Finding identity, lifecycle and risk scoring.

These are the rules that decide what a developer sees in their queue, so they are tested as
behaviour rather than as coverage: identity must survive a refactor, a suppression must not
quietly reopen, and the score must order the queue the way a security team would.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aegis_api.domain.entities.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    finding_identity,
    score_finding,
    stack_fingerprint,
)
from aegis_api.domain.errors import InvalidStateError

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

APPLICATION_FRAMES = [
    ("com.acme.UserRepository", "findByName", True),
    ("java.sql.Statement", "execute", False),
    ("org.springframework.web.Dispatcher", "doDispatch", False),
    ("com.acme.SearchController", "search", True),
]


def make_finding(**overrides: object) -> Finding:
    organization_id = overrides.pop("organization_id", uuid4())
    application_id = overrides.pop("application_id", uuid4())
    defaults: dict[str, object] = {
        "organization_id": organization_id,
        "application_id": application_id,
        "identity_hash": "a" * 64,
        "rule_key": "sql-injection",
        "title": "SQL injection in UserRepository",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.EXPLOITED,
        "sink_signature": "java.sql.Statement#execute(String)",
        "source_kind": "PARAMETER",
        "stack_hash": "b" * 64,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestStackFingerprint:
    def test_keeps_only_application_frames(self) -> None:
        # Framework frames churn with every dependency bump. Including them would make a
        # Spring upgrade look like a wave of new vulnerabilities.
        with_framework = stack_fingerprint(APPLICATION_FRAMES)
        without = stack_fingerprint([f for f in APPLICATION_FRAMES if f[2]])
        assert with_framework == without

    def test_which_frame_is_innermost_matters(self) -> None:
        # Reversing the stack changes which line is the vulnerable one, so the identity changes.
        reversed_frames = list(reversed([f for f in APPLICATION_FRAMES if f[2]]))
        assert stack_fingerprint(APPLICATION_FRAMES) != stack_fingerprint(reversed_frames)

    def test_ignores_frames_above_the_innermost(self) -> None:
        deep = [(f"com.acme.Layer{i}", "call", True) for i in range(12)]
        assert stack_fingerprint(deep) == stack_fingerprint(deep[:1])

    def test_two_call_paths_through_one_line_are_one_defect(self) -> None:
        # The case that prompted ADR-0012. A helper reached from two controllers is one broken
        # line, and fixing it must close one row rather than leave the second open.
        via_search = [
            ("com.acme.UserRepository", "buildQuery", True),
            ("com.acme.SearchController", "search", True),
        ]
        via_export = [
            ("com.acme.UserRepository", "buildQuery", True),
            ("com.acme.ExportController", "export", True),
        ]
        assert stack_fingerprint(via_search) == stack_fingerprint(via_export)

    def test_genuinely_different_lines_stay_distinct(self) -> None:
        # The other half of the trade: collapsing call paths must not collapse defects.
        assert stack_fingerprint([("com.acme.UserRepository", "buildQuery", True)]) != (
            stack_fingerprint([("com.acme.ReportRepository", "buildQuery", True)])
        )

    def test_a_stack_with_no_application_frames_still_hashes(self) -> None:
        # Third-party code calling a sink is a real, if unactionable, finding. It must not
        # crash the pipeline.
        assert stack_fingerprint([("java.sql.Statement", "execute", False)])


class TestIdentity:
    def _identity(self, **overrides: object) -> str:
        base: dict[str, object] = {
            "organization_id": uuid4(),
            "application_id": uuid4(),
            "rule_key": "sql-injection",
            "sink_signature": "java.sql.Statement#execute(String)",
            "source_kind": "PARAMETER",
            "stack_hash": "b" * 64,
        }
        base.update(overrides)
        return finding_identity(**base)  # type: ignore[arg-type]

    def test_is_stable_across_case_and_whitespace(self) -> None:
        organization_id, application_id = uuid4(), uuid4()
        left = self._identity(
            organization_id=organization_id,
            application_id=application_id,
            rule_key="SQL-Injection",
            sink_signature="java.sql.Statement#execute(String)",
            source_kind="parameter",
        )
        right = self._identity(
            organization_id=organization_id,
            application_id=application_id,
            rule_key="sql-injection",
            sink_signature="  java.sql.Statement#execute(String)  ",
            source_kind="PARAMETER",
        )
        assert left == right

    def test_ignores_a_line_number_suffix(self) -> None:
        organization_id, application_id = uuid4(), uuid4()
        # The agent must never send one, but a line number leaking into identity would
        # resurrect every finding on the next reformat.
        assert self._identity(
            organization_id=organization_id,
            application_id=application_id,
            sink_signature="java.sql.Statement#execute(String)",
        ) == self._identity(
            organization_id=organization_id,
            application_id=application_id,
            sink_signature="java.sql.Statement#execute(String):412",
        )

    def test_separates_tenants_with_identical_code(self) -> None:
        application_id = uuid4()
        assert self._identity(application_id=application_id) != self._identity(
            application_id=application_id
        )

    def test_is_keyed_on_application_not_environment(self) -> None:
        # There is no environment input at all: the same flaw in staging and production is one
        # flaw, and a developer fixing it should close one row rather than two.
        organization_id, application_id = uuid4(), uuid4()
        repeated = {
            "organization_id": organization_id,
            "application_id": application_id,
        }
        assert self._identity(**repeated) == self._identity(**repeated)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("rule_key", "command-injection"),
            ("sink_signature", "java.lang.Runtime#exec(String)"),
            ("source_kind", "HEADER"),
            ("stack_hash", "c" * 64),
        ],
    )
    def test_every_component_changes_identity(self, field: str, value: str) -> None:
        organization_id, application_id = uuid4(), uuid4()
        base = {"organization_id": organization_id, "application_id": application_id}
        assert self._identity(**base) != self._identity(**base, **{field: value})


class TestScoring:
    def _score(self, **overrides: object) -> float:
        base: dict[str, object] = {
            "severity": Severity.HIGH,
            "confidence": Confidence.CONFIRMED,
            "exposure_weight": 1.0,
            "criticality_weight": 1.0,
            "attack_observed": False,
            "occurrence_count": 1,
        }
        base.update(overrides)
        return score_finding(**base).value  # type: ignore[arg-type]

    def test_production_outranks_development_for_the_same_defect(self) -> None:
        assert self._score(exposure_weight=1.3) > self._score(exposure_weight=0.3)

    def test_exploited_outranks_suspected(self) -> None:
        assert self._score(confidence=Confidence.EXPLOITED) > self._score(
            confidence=Confidence.SUSPECTED
        )

    def test_traffic_volume_never_outweighs_severity(self) -> None:
        # The requirement that matters: a critical defect on a rarely-hit admin page must
        # still outrank a medium one on the landing page, however much traffic the latter sees.
        rare_critical = self._score(severity=Severity.CRITICAL, occurrence_count=1)
        busy_medium = self._score(severity=Severity.MEDIUM, occurrence_count=5_000_000)
        assert rare_critical > busy_medium

    def test_is_capped_at_ten(self) -> None:
        assert (
            self._score(
                severity=Severity.CRITICAL,
                confidence=Confidence.EXPLOITED,
                exposure_weight=1.3,
                criticality_weight=1.25,
                attack_observed=True,
                occurrence_count=1_000,
            )
            == 10.0
        )

    def test_explains_every_factor_that_moved_it(self) -> None:
        score = score_finding(
            severity=Severity.CRITICAL,
            confidence=Confidence.EXPLOITED,
            exposure_weight=1.3,
            criticality_weight=1.25,
            attack_observed=True,
            occurrence_count=10,
        )
        # A number a developer cannot interrogate is a number they argue with instead of act on.
        named = {name for name, _, _ in score.factors}
        assert named == {
            "severity",
            "confidence",
            "exposure",
            "business criticality",
            "active attack",
            "recurrence",
        }
        assert all(reason for _, _, reason in score.factors)

    def test_band_follows_the_score(self) -> None:
        assert (
            score_finding(
                severity=Severity.CRITICAL,
                confidence=Confidence.EXPLOITED,
                exposure_weight=1.3,
                criticality_weight=1.25,
                attack_observed=True,
                occurrence_count=1,
            ).band
            is Severity.CRITICAL
        )
        assert (
            score_finding(
                severity=Severity.INFO,
                confidence=Confidence.SUSPECTED,
                exposure_weight=0.3,
                criticality_weight=0.6,
                attack_observed=False,
                occurrence_count=1,
            ).band
            is Severity.INFO
        )


class TestOccurrences:
    def test_first_sighting_sets_both_timestamps(self) -> None:
        finding = make_finding()
        finding.record_occurrence(environment="QA", route_template="/x", observed_at=NOW)
        assert finding.first_seen_at == NOW
        assert finding.last_seen_at == NOW
        assert finding.occurrence_count == 1

    def test_collapses_repeats_into_one_defect(self) -> None:
        finding = make_finding()
        for index in range(100):
            finding.record_occurrence(
                environment="PRODUCTION",
                route_template="/users/search",
                observed_at=NOW + timedelta(seconds=index),
            )
        # One line of vulnerable code is one row, however many requests reach it.
        assert finding.occurrence_count == 100
        assert finding.environments_seen == ("PRODUCTION",)
        assert finding.route_templates == ("/users/search",)

    def test_remembers_each_environment_once(self) -> None:
        finding = make_finding()
        for environment in ["QA", "PRODUCTION", "QA", "STAGING"]:
            finding.record_occurrence(environment=environment, route_template="/x", observed_at=NOW)
        assert finding.environments_seen == ("QA", "PRODUCTION", "STAGING")

    def test_bounds_the_route_list(self) -> None:
        finding = make_finding()
        for index in range(50):
            finding.record_occurrence(
                environment="PRODUCTION", route_template=f"/route/{index}", observed_at=NOW
            )
        assert len(finding.route_templates) == Finding.MAX_ROUTES

    def test_recurrence_after_remediation_is_a_regression(self) -> None:
        finding = make_finding()
        finding.record_occurrence(environment="PRODUCTION", route_template="/x", observed_at=NOW)
        finding.transition(FindingStatus.REMEDIATED, actor_id=uuid4(), now=NOW)

        regressed = finding.record_occurrence(
            environment="PRODUCTION", route_template="/x", observed_at=NOW
        )

        # The fix did not hold. A team's second attempt at the same bug deserves to be visible.
        assert regressed
        assert finding.status is FindingStatus.OPEN
        assert finding.regressed
        assert finding.remediated_at is None

    @pytest.mark.parametrize("status", [FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK])
    def test_suppressed_findings_absorb_recurrences_without_reopening(
        self, status: FindingStatus
    ) -> None:
        finding = make_finding()
        finding.record_occurrence(environment="PRODUCTION", route_template="/x", observed_at=NOW)
        finding.transition(status, actor_id=uuid4(), now=NOW, note="reviewed and dismissed")
        before = finding.occurrence_count

        regressed = finding.record_occurrence(
            environment="PRODUCTION", route_template="/x", observed_at=NOW
        )

        # Reopening would erase a decision someone deliberately made. The separate counter is
        # what lets them see the suppression is still absorbing live traffic.
        assert not regressed
        assert finding.status is status
        assert finding.occurrence_count == before
        assert finding.suppressed_occurrence_count == 1


class TestLifecycle:
    def test_rejects_an_illegal_transition(self) -> None:
        finding = make_finding(status=FindingStatus.REMEDIATED)
        with pytest.raises(InvalidStateError, match="cannot move"):
            finding.transition(FindingStatus.FALSE_POSITIVE, actor_id=uuid4(), now=NOW)

    def test_transitioning_to_the_current_status_is_a_no_op(self) -> None:
        finding = make_finding()
        finding.transition(FindingStatus.OPEN, actor_id=uuid4(), now=NOW)
        assert finding.triaged_by is None

    @pytest.mark.parametrize("status", [FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK])
    def test_suppression_requires_a_reason(self, status: FindingStatus) -> None:
        finding = make_finding()
        # Someone will read this in six months wondering why a live vulnerability is dismissed.
        with pytest.raises(InvalidStateError, match="requires a reason"):
            finding.transition(status, actor_id=uuid4(), now=NOW, note="   ")

    def test_accepted_risk_expires_by_default(self) -> None:
        finding = make_finding()
        finding.transition(
            FindingStatus.ACCEPTED_RISK, actor_id=uuid4(), now=NOW, note="mitigated at the edge"
        )
        assert finding.accepted_until == NOW + timedelta(days=90)

    def test_an_expired_acceptance_returns_to_the_queue(self) -> None:
        finding = make_finding()
        finding.transition(
            FindingStatus.ACCEPTED_RISK,
            actor_id=uuid4(),
            now=NOW,
            note="mitigated at the edge",
            accepted_for=timedelta(days=30),
        )
        assert not finding.expire_acceptance(NOW + timedelta(days=29))
        assert finding.expire_acceptance(NOW + timedelta(days=31))
        assert finding.status is FindingStatus.OPEN
        assert finding.accepted_until is None

    def test_remediation_clears_a_previous_regression_flag(self) -> None:
        finding = make_finding(regressed=True)
        finding.transition(FindingStatus.REMEDIATED, actor_id=uuid4(), now=NOW)
        assert not finding.regressed
        assert finding.remediated_at == NOW

    def test_a_false_positive_can_be_reopened_when_the_call_was_wrong(self) -> None:
        finding = make_finding()
        finding.transition(
            FindingStatus.FALSE_POSITIVE, actor_id=uuid4(), now=NOW, note="test fixture"
        )
        finding.transition(FindingStatus.OPEN, actor_id=uuid4(), now=NOW)
        assert finding.status is FindingStatus.OPEN

    def test_open_in_production_is_what_pages_someone(self) -> None:
        finding = make_finding()
        finding.record_occurrence(environment="QA", route_template="/x", observed_at=NOW)
        assert not finding.is_open_in_production
        finding.record_occurrence(environment="PRODUCTION", route_template="/x", observed_at=NOW)
        assert finding.is_open_in_production

    def test_a_finding_must_have_a_title(self) -> None:
        with pytest.raises(InvalidStateError, match="title"):
            make_finding(title="   ")

    def test_a_finding_must_have_an_identity(self) -> None:
        with pytest.raises(InvalidStateError, match="identity"):
            make_finding(identity_hash="")


class TestWireParsing:
    """Reading the agent's wire format defensively.

    Every value here crosses a process boundary from code running inside a customer's
    application, so the parser's job is to be unsurprising rather than strict: an unreadable
    field costs evidence, never a crash.
    """

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("SEVERITY_CRITICAL", Severity.CRITICAL),
            ("critical", Severity.CRITICAL),
            ("", Severity.MEDIUM),
            (None, Severity.MEDIUM),
            ("SEVERITY_NONSENSE", Severity.MEDIUM),
        ],
    )
    def test_severity_falls_back_rather_than_raising(self, raw: object, expected: Severity) -> None:
        from aegis_api.application.findings import _severity

        assert _severity(raw) is expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CONFIDENCE_EXPLOITED", Confidence.EXPLOITED),
            ("", Confidence.SUSPECTED),
            ("garbage", Confidence.SUSPECTED),
        ],
    )
    def test_unknown_confidence_is_the_least_alarming_value(
        self, raw: object, expected: Confidence
    ) -> None:
        # Defaulting upward would inflate risk scores off the back of a malformed field.
        from aegis_api.application.findings import _confidence

        assert _confidence(raw) is expected

    def test_source_kind_comes_from_the_first_range(self) -> None:
        from aegis_api.application.findings import _primary_source_kind

        assert (
            _primary_source_kind(
                [
                    {"source": "SOURCE_KIND_PARAMETER"},
                    {"source": "SOURCE_KIND_HEADER"},
                ]
            )
            == "PARAMETER"
        )
        assert _primary_source_kind([]) == "UNKNOWN"
        assert _primary_source_kind("not a list") == "UNKNOWN"

    def test_a_title_names_the_application_method(self) -> None:
        from aegis_api.application.findings import _title

        assert (
            _title(
                "sql-injection",
                [
                    ("java.sql.Statement", "execute", False),
                    ("com.acme.data.UserRepository", "findByName", True),
                ],
            )
            == "SQL injection in UserRepository.findByName"
        )

    def test_a_title_degrades_to_the_rule_when_no_application_frame_exists(self) -> None:
        from aegis_api.application.findings import _title

        # Third-party code reaching a sink is still a finding; it just cannot be named.
        assert _title("sql-injection", [("java.sql.Statement", "execute", False)]) == (
            "SQL injection"
        )

    def test_a_missing_timestamp_falls_back_to_now(self) -> None:
        from aegis_api.application.findings import _observed_at

        assert _observed_at({"occurred_at_ms": "nonsense"}).year >= 2026
        assert _observed_at({}).year >= 2026

    def test_malformed_ranges_and_frames_yield_nothing_rather_than_raising(self) -> None:
        from aegis_api.application.findings import _frames, _ranges, _stack_frames

        assert _ranges("not a list") == []
        assert _frames({"not": "a list"}) == []
        assert _stack_frames(None) == []
