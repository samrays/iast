"""Publishing a signed catalogue, through the real crypto and the real database."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import text
from tests.conftest import Tenant

from aegis_api.application.rules import PublishRuleBundle
from aegis_api.container import Container
from aegis_api.domain.entities.findings import Severity
from aegis_api.domain.entities.rules import BundleRejectedError, Rule, RuleBundle
from aegis_api.infrastructure.security.bundle_signing import (
    SigningKeyUnavailableError,
    generate_keypair,
    sign_with,
    verifier_for,
)

pytestmark = [pytest.mark.integration]

PUBLISHED_AT = datetime(2026, 8, 1, tzinfo=UTC)
PRIVATE_KEY, PUBLIC_KEY = generate_keypair()


@pytest.fixture(autouse=True)
async def _empty_catalogue(container: Container):
    """Start every test with no installed bundle.

    Unlike tenant data, `rule_bundles` is global — that is the point of it — so it is not
    rolled back with a tenant fixture, and a version installed by one test would make the
    monotonic check reject a lower version in the next. Tests that share global state have to
    reset it themselves.
    """
    async with container.unit_of_work() as uow:
        await uow.session.execute(text("DELETE FROM rule_bundles"))
        await uow.commit()
    yield


def bundle(version: int = 1, *, title: str = "SQL injection (updated guidance)") -> RuleBundle:
    return RuleBundle(
        version=version,
        published_at=PUBLISHED_AT,
        rules=(
            Rule(
                key="sql-injection",
                title=title,
                severity=Severity.CRITICAL,
                cwe_id=89,
                description="Untrusted input reaches a SQL statement unbound.",
                remediation="Bind the value as a parameter.",
            ),
        ),
    )


async def publish(container: Container, candidate: RuleBundle, *, key: str = PRIVATE_KEY) -> None:
    payload = candidate.canonical_bytes()
    await PublishRuleBundle(container.unit_of_work(), verifier_for(PUBLIC_KEY)).execute(
        canonical_bytes=payload, signature=sign_with(key, payload)
    )


class TestPublishing:
    async def test_a_signed_bundle_replaces_the_built_in_catalogue(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        before = (await client.get("/api/v1/rules", headers=tenant.headers)).json()
        assert len(before) == 11

        await publish(container, bundle())

        after = (await client.get("/api/v1/rules", headers=tenant.headers)).json()
        # The published bundle is now the catalogue, not an addition to it.
        assert len(after) == 1
        assert after[0]["title"] == "SQL injection (updated guidance)"
        assert after[0]["remediation"] == "Bind the value as a parameter."

    async def test_a_bundle_signed_by_the_wrong_key_is_refused(self, container: Container) -> None:
        other_private, _ = generate_keypair()
        with pytest.raises(BundleRejectedError, match="signature"):
            await publish(container, bundle(), key=other_private)

    async def test_tampering_after_signing_is_refused(self, container: Container) -> None:
        original = bundle()
        signature = sign_with(PRIVATE_KEY, original.canonical_bytes())
        weakened = bundle(title="SQL injection")  # one byte of intent, different bytes

        with pytest.raises(BundleRejectedError):
            await PublishRuleBundle(container.unit_of_work(), verifier_for(PUBLIC_KEY)).execute(
                canonical_bytes=weakened.canonical_bytes(), signature=signature
            )

    async def test_a_non_canonical_bundle_is_refused_before_verification(
        self, container: Container
    ) -> None:
        # Pretty-printed JSON that parses to the same rules. Signing it would produce a
        # signature that never verifies again, so it is refused with a reason rather than
        # accepted and mysteriously broken later.
        pretty = (
            b'{\n  "version": 1,\n  "published_at": "2026-08-01T00:00:00+00:00",\n  "rules": []\n}'
        )
        with pytest.raises(BundleRejectedError, match="canonical"):
            await PublishRuleBundle(container.unit_of_work(), verifier_for(PUBLIC_KEY)).execute(
                canonical_bytes=pretty, signature=b"\x00" * 64
            )

    async def test_rollback_to_an_older_signed_bundle_is_refused(
        self, container: Container
    ) -> None:
        await publish(container, bundle(version=5))
        # Genuinely signed, genuinely older. Re-presenting it removes every rule added since.
        with pytest.raises(BundleRejectedError, match="not newer"):
            await publish(container, bundle(version=2))

    async def test_replaying_the_installed_version_is_refused(self, container: Container) -> None:
        await publish(container, bundle(version=7))
        with pytest.raises(BundleRejectedError, match="not newer"):
            await publish(container, bundle(version=7))

    async def test_a_newer_bundle_installs_over_an_older_one(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        await publish(container, bundle(version=1, title="First"))
        await publish(container, bundle(version=2, title="Second"))

        rules = (await client.get("/api/v1/rules", headers=tenant.headers)).json()
        assert rules[0]["title"] == "Second"

    async def test_a_tenants_opt_out_survives_a_bundle_upgrade(
        self, client: httpx.AsyncClient, container: Container, tenant: Tenant
    ) -> None:
        await client.put(
            "/api/v1/rules/sql-injection",
            headers=tenant.headers,
            json={"enabled": False, "reason": "Handled by the data-access layer."},
        )
        await publish(container, bundle(version=3))

        rules = (await client.get("/api/v1/rules", headers=tenant.headers)).json()
        # A new catalogue must not quietly re-enable what a customer deliberately switched off.
        assert rules[0]["enabled"] is False
        assert "data-access" in rules[0]["disabled_reason"]


class TestKeyHandling:
    def test_a_missing_key_refuses_to_build_a_verifier(self) -> None:
        # Not a permissive verifier: a deployment with no key must fail to install bundles
        # rather than install them unchecked.
        with pytest.raises(SigningKeyUnavailableError, match="No rule-signing public key"):
            verifier_for("")

    def test_a_malformed_key_refuses_too(self) -> None:
        with pytest.raises(SigningKeyUnavailableError, match="not usable"):
            verifier_for("this-is-not-base64-ed25519")

    def test_a_generated_pair_round_trips(self) -> None:
        private, public = generate_keypair()
        verifier_for(public)(b"payload", sign_with(private, b"payload"))
