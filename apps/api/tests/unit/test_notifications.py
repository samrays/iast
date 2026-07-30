"""Webhook signing and destination validation.

Both halves of "the customer gives you a URL and you POST to it" are dangerous, so both halves
are tested adversarially: forging or replaying a delivery, and pointing our infrastructure at
somewhere it should not go.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aegis_api.domain.entities.notifications import (
    NotificationEvent,
    WebhookEndpoint,
    generate_secret,
    sign_payload,
    validate_destination,
    verify_signature,
)
from aegis_api.domain.errors import InvalidStateError, ValidationError

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
TIMESTAMP = int(NOW.timestamp())
BODY = b'{"event":"finding.opened","severity":"CRITICAL"}'
SECRET = "s3cret-signing-key"


def make_endpoint(**overrides: object) -> WebhookEndpoint:
    defaults: dict[str, object] = {
        "organization_id": uuid4(),
        "url": "https://hooks.example.com/aegis",
        "secret": SECRET,
        "events": (NotificationEvent.FINDING_OPENED,),
    }
    defaults.update(overrides)
    return WebhookEndpoint(**defaults)  # type: ignore[arg-type]


class TestSigning:
    def test_a_genuine_delivery_verifies(self) -> None:
        signature = sign_payload(SECRET, timestamp=TIMESTAMP, body=BODY)
        assert verify_signature(SECRET, timestamp=TIMESTAMP, body=BODY, signature=signature)

    def test_a_tampered_body_does_not(self) -> None:
        signature = sign_payload(SECRET, timestamp=TIMESTAMP, body=BODY)
        forged = b'{"event":"finding.opened","severity":"INFO"}'
        # Downgrading the severity of a real alert is the cheapest useful forgery.
        assert not verify_signature(SECRET, timestamp=TIMESTAMP, body=forged, signature=signature)

    def test_the_timestamp_is_inside_the_signature(self) -> None:
        signature = sign_payload(SECRET, timestamp=TIMESTAMP, body=BODY)
        # Signing only the body would leave the timestamp editable, so a receiver checking
        # freshness would be checking a value the attacker controls. Replay would be free.
        assert not verify_signature(
            SECRET, timestamp=TIMESTAMP + 3600, body=BODY, signature=signature
        )

    def test_another_tenants_secret_does_not_verify(self) -> None:
        signature = sign_payload(SECRET, timestamp=TIMESTAMP, body=BODY)
        assert not verify_signature(
            "someone-elses-secret", timestamp=TIMESTAMP, body=BODY, signature=signature
        )

    def test_the_signature_is_versioned(self) -> None:
        # Without a version there is no way to change the algorithm later without breaking
        # every receiver simultaneously.
        assert sign_payload(SECRET, timestamp=TIMESTAMP, body=BODY).startswith("v1=")

    def test_generated_secrets_are_unique_and_long(self) -> None:
        secrets_seen = {generate_secret() for _ in range(50)}
        assert len(secrets_seen) == 50
        assert all(len(secret) >= 32 for secret in secrets_seen)


class TestDestinationValidation:
    def test_accepts_an_ordinary_https_endpoint(self) -> None:
        assert validate_destination("https://hooks.example.com/aegis")

    def test_refuses_plaintext(self) -> None:
        # The payload names which of the customer's applications is vulnerable and how.
        with pytest.raises(ValidationError, match="https"):
            validate_destination("http://hooks.example.com/aegis")

    @pytest.mark.parametrize(
        "url",
        [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/admin",
            "https://10.0.0.5/internal",
            "https://192.168.1.1/",
            "https://172.16.0.1/",
            "https://[::1]/",
            "https://0.0.0.0/",
        ],
    )
    def test_refuses_addresses_inside_our_network(self, url: str) -> None:
        # This is the actual attack: a tenant who can create a webhook can otherwise make our
        # servers issue requests from our network position. 169.254.169.254 is the cloud
        # metadata service — unauthenticated, internal-only, full of credentials.
        with pytest.raises(ValidationError, match="private, loopback or link-local"):
            validate_destination(url)

    @pytest.mark.parametrize("host", ["metadata.google.internal", "localhost", "instance-data"])
    def test_refuses_known_metadata_hostnames(self, host: str) -> None:
        # Named rather than numeric, so the IP checks would not catch them.
        with pytest.raises(ValidationError, match="not a permitted"):
            validate_destination(f"https://{host}/computeMetadata/v1/")

    def test_allows_loopback_only_when_explicitly_permitted(self) -> None:
        # For local development, where the receiver genuinely is on localhost.
        assert validate_destination("https://127.0.0.1:9000/hook", allow_private=True)

    def test_refuses_a_url_with_no_host(self) -> None:
        with pytest.raises(ValidationError, match="host"):
            validate_destination("https:///just-a-path")

    def test_a_hostname_is_accepted_and_resolved_later(self) -> None:
        # Documented limitation: DNS can answer differently at delivery time. Closing that
        # needs resolution pinning in the HTTP client, not here.
        assert validate_destination("https://webhook.customer.example/aegis")


class TestEndpointLifecycle:
    def test_must_subscribe_to_something(self) -> None:
        with pytest.raises(ValidationError, match="at least one event"):
            make_endpoint(events=())

    def test_only_delivers_subscribed_events(self) -> None:
        endpoint = make_endpoint(events=(NotificationEvent.ATTACK_DETECTED,))
        assert endpoint.subscribes_to(NotificationEvent.ATTACK_DETECTED)
        assert not endpoint.subscribes_to(NotificationEvent.FINDING_OPENED)

    def test_a_disabled_endpoint_subscribes_to_nothing(self) -> None:
        endpoint = make_endpoint(enabled=False)
        assert not endpoint.subscribes_to(NotificationEvent.FINDING_OPENED)

    def test_success_clears_the_failure_streak(self) -> None:
        endpoint = make_endpoint()
        endpoint.record_failure("connection refused")
        endpoint.record_success(NOW)
        assert endpoint.consecutive_failures == 0
        assert endpoint.last_failure_reason == ""
        assert endpoint.last_delivered_at == NOW

    def test_a_persistently_dead_endpoint_switches_itself_off(self) -> None:
        endpoint = make_endpoint()
        for _ in range(WebhookEndpoint.FAILURES_BEFORE_DISABLE - 1):
            assert not endpoint.record_failure("timeout")
        # A receiver gone for a day should stop costing a delivery attempt per finding.
        assert endpoint.record_failure("timeout")
        assert not endpoint.enabled

    def test_rotating_issues_a_different_secret(self) -> None:
        endpoint = make_endpoint()
        original = endpoint.secret
        rotated = endpoint.rotate_secret()
        assert rotated != original
        assert endpoint.secret == rotated

    def test_a_disabled_endpoint_cannot_rotate(self) -> None:
        endpoint = make_endpoint(enabled=False)
        with pytest.raises(InvalidStateError, match="Enable the endpoint"):
            endpoint.rotate_secret()
