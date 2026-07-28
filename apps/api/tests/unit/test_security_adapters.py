"""Hashing, encryption, tokens and TOTP."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp
import pytest

from aegis_api.config import Settings
from aegis_api.domain.errors import TokenError
from aegis_api.domain.value_objects import new_id
from aegis_api.infrastructure.clock import FrozenClock, SystemClock
from aegis_api.infrastructure.security import (
    Argon2PasswordHasher,
    FernetCipher,
    JwtAccessTokenCodec,
    OpaqueTokenGenerator,
    PyOtpTotpService,
)
from aegis_api.infrastructure.security.cipher import SecretDecryptionError

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


def token_now() -> datetime:
    """Real wall-clock time.

    JWT validation rejects an ``iat`` in the future and honours ``exp``, so token tests
    must anchor to now at call time — a module-level constant would expire mid-suite.
    """
    return datetime.now(UTC)


# Cheap parameters keep the suite fast; production defaults are asserted separately.
HASHER = Argon2PasswordHasher(time_cost=1, memory_cost_kib=8192, parallelism=1)


class TestArgon2PasswordHasher:
    def test_round_trip(self) -> None:
        hashed = HASHER.hash("correct-horse-battery-77")
        assert hashed.startswith("$argon2id$")
        assert HASHER.verify("correct-horse-battery-77", hashed)
        assert not HASHER.verify("wrong", hashed)

    def test_salts_are_unique(self) -> None:
        assert HASHER.hash("same") != HASHER.hash("same")

    def test_malformed_hash_is_rejected_not_raised(self) -> None:
        assert not HASHER.verify("x", "not-a-hash")
        assert HASHER.needs_rehash("not-a-hash")

    def test_rehash_detected_when_parameters_increase(self) -> None:
        weak = Argon2PasswordHasher(time_cost=1, memory_cost_kib=8192, parallelism=1)
        strong = Argon2PasswordHasher(time_cost=3, memory_cost_kib=16384, parallelism=1)
        assert strong.needs_rehash(weak.hash("password-for-rehash-test"))

    def test_dummy_verify_is_safe_to_call(self) -> None:
        # Exists so an unknown account costs the same wall time as a known one (T-07).
        HASHER.dummy_verify()

    def test_production_defaults_meet_owasp_guidance(self) -> None:
        settings = Settings(environment="local")
        assert settings.argon2_memory_cost_kib >= 65536
        assert settings.argon2_time_cost >= 3


class TestOpaqueTokenGenerator:
    def test_generates_high_entropy_tokens(self) -> None:
        generator = OpaqueTokenGenerator()
        token, digest = generator.generate()
        assert len(token) >= 40
        assert generator.hash(token) == digest

    def test_tokens_are_unique(self) -> None:
        generator = OpaqueTokenGenerator()
        assert len({generator.generate()[0] for _ in range(500)}) == 500


class TestFernetCipher:
    def test_round_trip(self) -> None:
        cipher = FernetCipher(["a-local-development-passphrase"])
        assert cipher.decrypt(cipher.encrypt("JBSWY3DPEHPK3PXP")) == "JBSWY3DPEHPK3PXP"

    def test_ciphertext_differs_between_calls(self) -> None:
        cipher = FernetCipher(["a-local-development-passphrase"])
        assert cipher.encrypt("same") != cipher.encrypt("same")

    def test_supports_key_rotation(self) -> None:
        old = FernetCipher(["old-key-material"])
        rotated = FernetCipher(["new-key-material", "old-key-material"])
        assert rotated.decrypt(old.encrypt("secret")) == "secret"

    def test_unknown_key_fails_closed(self) -> None:
        produced = FernetCipher(["key-one"]).encrypt("secret")
        with pytest.raises(SecretDecryptionError):
            FernetCipher(["key-two"]).decrypt(produced)

    def test_rejects_empty_key_set(self) -> None:
        with pytest.raises(ValueError, match="encryption key"):
            FernetCipher([])


class TestJwtAccessTokenCodec:
    def _codec(self) -> JwtAccessTokenCodec:
        return JwtAccessTokenCodec(secret="s" * 48, issuer="https://api.test")

    def test_issue_and_decode(self) -> None:
        codec = self._codec()
        subject, org, session = new_id(), new_id(), new_id()
        # Pin the instant: calling token_now() twice would give two different values.
        issued_at = token_now()
        token, expires = codec.issue(
            subject=subject,
            organization_id=org,
            session_id=session,
            permissions=frozenset({"app:read"}),
            mfa_satisfied=True,
            ttl_seconds=900,
            now=issued_at,
        )
        claims = codec.decode(token, audience="aegis:user")
        assert claims["sub"] == str(subject)
        assert claims["org"] == str(org)
        assert claims["sid"] == str(session)
        assert claims["perms"] == ["app:read"]
        assert claims["mfa"] is True
        assert expires == issued_at + timedelta(seconds=900)

    def test_wrong_audience_is_rejected(self) -> None:
        # Audience separation is what stops an agent token working on a user route (T-06).
        codec = self._codec()
        token = codec.issue_challenge(
            subject=new_id(),
            organization_id=new_id(),
            ttl_seconds=60,
            now=token_now(),
            purpose="agent",
        )
        with pytest.raises(TokenError):
            codec.decode(token, audience="aegis:user")
        assert codec.decode(token, audience="aegis:agent")["purpose"] == "agent"

    def test_expired_token_is_rejected(self) -> None:
        codec = self._codec()
        token, _ = codec.issue(
            subject=new_id(),
            organization_id=new_id(),
            session_id=new_id(),
            permissions=frozenset(),
            mfa_satisfied=False,
            ttl_seconds=1,
            now=token_now() - timedelta(days=1),
        )
        with pytest.raises(TokenError):
            codec.decode(token, audience="aegis:user")

    def test_tampered_signature_is_rejected(self) -> None:
        codec = self._codec()
        token, _ = codec.issue(
            subject=new_id(),
            organization_id=new_id(),
            session_id=new_id(),
            permissions=frozenset(),
            mfa_satisfied=False,
            ttl_seconds=900,
            now=token_now(),
        )
        with pytest.raises(TokenError):
            codec.decode(token[:-4] + "AAAA", audience="aegis:user")

    def test_foreign_issuer_is_rejected(self) -> None:
        other = JwtAccessTokenCodec(secret="s" * 48, issuer="https://evil.test")
        token = other.issue_challenge(
            subject=new_id(),
            organization_id=new_id(),
            ttl_seconds=60,
            now=token_now(),
            purpose="mfa",
        )
        with pytest.raises(TokenError):
            self._codec().decode(token, audience="aegis:mfa_challenge")

    def test_unknown_purpose_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="purpose"):
            self._codec().issue_challenge(
                subject=new_id(),
                organization_id=new_id(),
                ttl_seconds=60,
                now=token_now(),
                purpose="nonsense",
            )

    def test_asymmetric_requires_both_keys(self) -> None:
        with pytest.raises(ValueError, match="private and a public key"):
            JwtAccessTokenCodec(secret="", algorithm="RS256")


class TestTotp:
    def test_accepts_a_current_code(self) -> None:
        service = PyOtpTotpService()
        secret = service.generate_secret()
        code = pyotp.TOTP(secret).at(NOW)
        assert service.verify(secret, code, now=NOW)

    def test_accepts_one_period_of_drift(self) -> None:
        service = PyOtpTotpService(valid_window=1)
        secret = service.generate_secret()
        code = pyotp.TOTP(secret).at(NOW - timedelta(seconds=30))
        assert service.verify(secret, code, now=NOW)

    def test_rejects_a_stale_code(self) -> None:
        service = PyOtpTotpService(valid_window=1)
        secret = service.generate_secret()
        code = pyotp.TOTP(secret).at(NOW - timedelta(minutes=5))
        assert not service.verify(secret, code, now=NOW)

    @pytest.mark.parametrize("code", ["", "abcdef", "12345", "1234567"])
    def test_rejects_malformed_codes(self, code: str) -> None:
        service = PyOtpTotpService()
        assert not service.verify(service.generate_secret(), code, now=NOW)

    def test_provisioning_uri_is_scannable(self) -> None:
        service = PyOtpTotpService()
        uri = service.provisioning_uri(
            service.generate_secret(), account="owner@aegis.dev", issuer="Aegis IAST"
        )
        assert uri.startswith("otpauth://totp/")
        assert "issuer=Aegis%20IAST" in uri


class TestClock:
    def test_system_clock_is_timezone_aware(self) -> None:
        assert SystemClock().now().tzinfo is not None

    def test_frozen_clock_controls_time(self) -> None:
        clock = FrozenClock(NOW)
        assert clock.now() == NOW
        clock.advance(60)
        assert clock.now() == NOW + timedelta(seconds=60)

    def test_frozen_clock_rejects_naive_datetimes(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            FrozenClock(datetime(2026, 1, 1))  # noqa: DTZ001 - the point of the test
