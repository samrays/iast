"""The rule catalogue.

These are security tests. The catalogue decides what gets detected, so the interesting cases
are the ones where somebody is trying to make it decide less.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_api.domain.entities.findings import Severity
from aegis_api.domain.entities.rules import (
    BUILTIN_BUNDLE_VERSION,
    BundleRejectedError,
    Rule,
    RuleBundle,
    TenantRuleSettings,
    accept_bundle,
    builtin_catalogue,
)
from aegis_api.domain.errors import InvalidStateError, ValidationError

NOW = datetime(2026, 7, 29, tzinfo=UTC)

SIGNING_KEY = Ed25519PrivateKey.generate()
OTHER_KEY = Ed25519PrivateKey.generate()


def verifier(key: Ed25519PrivateKey):
    public = key.public_key()

    def verify(message: bytes, signature: bytes) -> None:
        public.verify(signature, message)

    return verify


def make_bundle(version: int = 1, *, rules: tuple[Rule, ...] | None = None) -> RuleBundle:
    return RuleBundle(
        version=version,
        rules=rules
        or (
            Rule(key="sql-injection", title="SQL injection", severity=Severity.CRITICAL, cwe_id=89),
            Rule(key="reflected-xss", title="Reflected XSS", severity=Severity.HIGH, cwe_id=79),
        ),
        published_at=NOW,
    )


def sign(bundle: RuleBundle, key: Ed25519PrivateKey = SIGNING_KEY) -> bytes:
    return key.sign(bundle.canonical_bytes())


class TestCanonicalForm:
    def test_round_trips_byte_for_byte(self) -> None:
        # Equality of the parsed object is the wrong assertion: canonical_bytes sorts rules,
        # so a round trip returns them sorted. What signing depends on is that re-encoding a
        # decoded bundle produces the identical bytes — otherwise a verifier and a publisher
        # could disagree about what was signed.
        original = make_bundle().canonical_bytes()
        assert RuleBundle.from_canonical_bytes(original).canonical_bytes() == original

    def test_round_trip_preserves_every_field(self) -> None:
        bundle = make_bundle()
        parsed = RuleBundle.from_canonical_bytes(bundle.canonical_bytes())
        assert parsed.version == bundle.version
        assert parsed.published_at == bundle.published_at
        assert {r.key for r in parsed.rules} == {r.key for r in bundle.rules}
        assert parsed.rule("sql-injection") == bundle.rule("sql-injection")

    def test_is_independent_of_rule_order(self) -> None:
        # Otherwise a publisher reordering its source list would invalidate a valid signature.
        rules = make_bundle().rules
        assert (
            make_bundle(rules=rules).canonical_bytes()
            == make_bundle(rules=tuple(reversed(rules))).canonical_bytes()
        )

    def test_changes_when_any_rule_changes(self) -> None:
        original = make_bundle()
        weakened = make_bundle(
            rules=(
                Rule(key="sql-injection", title="SQL injection", severity=Severity.LOW, cwe_id=89),
                original.rules[1],
            )
        )
        # Downgrading a critical rule to low must not produce bytes that keep the old signature.
        assert original.canonical_bytes() != weakened.canonical_bytes()

    def test_rejects_a_duplicated_key(self) -> None:
        duplicate = Rule(key="sql-injection", title="A", severity=Severity.LOW)
        with pytest.raises(ValidationError, match="repeat"):
            make_bundle(rules=(duplicate, duplicate))

    def test_rejects_a_key_that_is_not_normalised(self) -> None:
        # Keys reach the finding identity hash; a case variant would mint a second identity
        # for the same defect.
        with pytest.raises(ValidationError, match="lower-case"):
            Rule(key="SQL-Injection", title="A", severity=Severity.LOW)


class TestAcceptance:
    def test_accepts_a_correctly_signed_bundle(self) -> None:
        bundle = make_bundle()
        assert (
            accept_bundle(
                candidate=bundle,
                signature=sign(bundle),
                verify=verifier(SIGNING_KEY),
                installed_version=None,
            )
            is bundle
        )

    def test_refuses_a_bundle_signed_by_the_wrong_key(self) -> None:
        bundle = make_bundle()
        with pytest.raises(BundleRejectedError, match="signature"):
            accept_bundle(
                candidate=bundle,
                signature=sign(bundle, OTHER_KEY),
                verify=verifier(SIGNING_KEY),
                installed_version=None,
            )

    def test_refuses_a_bundle_whose_rules_were_altered_after_signing(self) -> None:
        # The attack this exists for: strip a rule so the flaw you intend to exploit stops
        # being detected, and do it without touching the console.
        original = make_bundle()
        signature = sign(original)
        tampered = make_bundle(rules=(original.rules[1],))

        with pytest.raises(BundleRejectedError):
            accept_bundle(
                candidate=tampered,
                signature=signature,
                verify=verifier(SIGNING_KEY),
                installed_version=None,
            )

    def test_refuses_a_genuinely_signed_older_bundle(self) -> None:
        # Rollback. The signature is valid — that is the point. Re-presenting version 1 after
        # version 5 removes every rule added since, and no signature check can catch it.
        old = make_bundle(version=1)
        with pytest.raises(BundleRejectedError, match="not newer"):
            accept_bundle(
                candidate=old,
                signature=sign(old),
                verify=verifier(SIGNING_KEY),
                installed_version=5,
            )

    def test_refuses_a_replay_of_the_installed_version(self) -> None:
        same = make_bundle(version=5)
        with pytest.raises(BundleRejectedError, match="not newer"):
            accept_bundle(
                candidate=same,
                signature=sign(same),
                verify=verifier(SIGNING_KEY),
                installed_version=5,
            )

    def test_checks_the_signature_before_the_version(self) -> None:
        # Comparing versions first would let an unauthenticated caller probe which version is
        # installed by watching which error comes back.
        forged = make_bundle(version=1)
        with pytest.raises(BundleRejectedError, match="signature"):
            accept_bundle(
                candidate=forged,
                signature=b"\x00" * 64,
                verify=verifier(SIGNING_KEY),
                installed_version=99,
            )

    def test_a_verifier_that_raises_anything_is_a_rejection(self) -> None:
        def broken(_message: bytes, _signature: bytes) -> None:
            raise InvalidSignature("no")

        with pytest.raises(BundleRejectedError):
            accept_bundle(
                candidate=make_bundle(),
                signature=b"",
                verify=broken,
                installed_version=None,
            )


class TestTenantSettings:
    def test_rules_are_on_unless_switched_off(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        # A catalogue defaulting to off ships a product that detects nothing until configured,
        # and the first thing anybody notices is a clean report.
        assert settings.is_enabled("sql-injection")

    def test_disabling_requires_a_reason(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        with pytest.raises(InvalidStateError, match="reason"):
            settings.disable("log-injection", reason="   ")

    def test_disabling_hides_the_rule_from_the_effective_set(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        settings.disable("reflected-xss", reason="Rendered by a framework that escapes.")

        effective = settings.effective_rules(make_bundle())
        assert [rule.key for rule in effective] == ["sql-injection"]

    def test_a_disabled_rule_survives_a_bundle_upgrade(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        settings.disable("reflected-xss", reason="Handled at the edge.")

        upgraded = make_bundle(
            version=2,
            rules=(
                *make_bundle().rules,
                Rule(key="ssrf", title="SSRF", severity=Severity.HIGH, cwe_id=918),
            ),
        )
        effective = {rule.key for rule in settings.effective_rules(upgraded)}
        # The new rule arrives on; the tenant's decision is not quietly reverted.
        assert effective == {"sql-injection", "ssrf"}

    def test_re_enabling_clears_the_reason(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        settings.disable("ssrf", reason="temporary")
        settings.enable("ssrf")
        assert settings.is_enabled("ssrf")
        assert "ssrf" not in settings.disabled

    def test_bounds_how_much_can_be_switched_off(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        for index in range(TenantRuleSettings.MAX_DISABLED):
            settings.disable(f"rule-{index}", reason="bulk")
        with pytest.raises(InvalidStateError, match="At most"):
            settings.disable("one-too-many", reason="bulk")

    def test_updating_an_existing_reason_is_not_a_new_entry(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        for index in range(TenantRuleSettings.MAX_DISABLED):
            settings.disable(f"rule-{index}", reason="bulk")
        # At the ceiling, revising a reason must still work — it is not adding anything.
        settings.disable("rule-0", reason="revised")
        assert settings.disabled["rule-0"] == "revised"


class TestBuiltinCatalogue:
    def test_covers_every_rule_the_agent_can_report(self) -> None:
        from aegis_api.application.findings import TITLE_BY_RULE

        keys = {rule.key for rule in builtin_catalogue(NOW).rules}
        # A rule the agent emits but the catalogue does not know would arrive as a finding
        # nobody can describe, filter or switch off.
        assert keys == set(TITLE_BY_RULE)

    def test_agrees_with_the_worker_about_cwe_ids(self) -> None:
        from aegis_api.application.findings import CWE_BY_RULE

        for rule in builtin_catalogue(NOW).rules:
            assert rule.cwe_id == CWE_BY_RULE[rule.key], rule.key

    def test_is_version_zero_so_any_published_bundle_supersedes_it(self) -> None:
        builtin = builtin_catalogue(NOW)
        assert builtin.version == BUILTIN_BUNDLE_VERSION == 0
        # The first real bundle must install without a special case in the monotonic check.
        first = make_bundle(version=1)
        assert (
            accept_bundle(
                candidate=first,
                signature=sign(first),
                verify=verifier(SIGNING_KEY),
                installed_version=builtin.version,
            )
            is first
        )

    def test_every_rule_explains_itself(self) -> None:
        # These strings are what a developer reads in a pull request comment, so an empty one
        # is a finding with no explanation.
        for rule in builtin_catalogue(NOW).rules:
            assert rule.title
            assert rule.description

    def test_ships_detecting_rather_than_waiting_to_be_configured(self) -> None:
        settings = TenantRuleSettings(organization_id=uuid4())
        effective = settings.effective_rules(builtin_catalogue(NOW))
        assert len(effective) == len(builtin_catalogue(NOW).rules)
