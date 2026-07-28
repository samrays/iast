"""Password, lockout and inventory policy behaviour."""

from __future__ import annotations

import pytest

from aegis_api.domain.errors import WeakPasswordError
from aegis_api.domain.policies import InventoryPolicy, LockoutPolicy, PasswordPolicy


class TestPasswordPolicy:
    def test_accepts_a_long_passphrase(self) -> None:
        PasswordPolicy().validate("correct horse battery staple")

    def test_reports_every_failure_at_once(self) -> None:
        # Reporting one rule at a time turns password creation into a guessing game.
        with pytest.raises(WeakPasswordError) as excinfo:
            PasswordPolicy(require_uppercase=True, require_digit=True).validate("short")
        assert len(excinfo.value.failures) >= 3

    @pytest.mark.parametrize("password", ["password123", "qwerty123456", "letmein12345"])
    def test_rejects_common_passwords(self, password: str) -> None:
        with pytest.raises(WeakPasswordError):
            PasswordPolicy().validate(password)

    def test_rejects_low_character_variety(self) -> None:
        with pytest.raises(WeakPasswordError) as excinfo:
            PasswordPolicy().validate("aaaaaaaaaaaaaaa")
        assert any("distinct" in f for f in excinfo.value.failures)

    @pytest.mark.parametrize("password", ["myabcdefghij2026", "zzz12345678zzz"])
    def test_rejects_sequences(self, password: str) -> None:
        with pytest.raises(WeakPasswordError) as excinfo:
            PasswordPolicy().validate(password)
        assert any("sequence" in f for f in excinfo.value.failures)

    def test_rejects_password_containing_context(self) -> None:
        # The first thing an attacker tries is the user's own name or organization.
        with pytest.raises(WeakPasswordError) as excinfo:
            PasswordPolicy().validate("cyberplural-2026!", context=("cyberplural",))
        assert any("organization" in f for f in excinfo.value.failures)

    def test_short_context_tokens_are_ignored(self) -> None:
        # A three-letter token would match almost anything; only meaningful tokens count.
        PasswordPolicy().validate("thundering-mongoose-91", context=("ops",))

    def test_enforces_maximum_length(self) -> None:
        with pytest.raises(WeakPasswordError):
            PasswordPolicy(max_length=32).validate("x9" * 40)

    @pytest.mark.parametrize(
        ("policy", "password", "expected_fragment"),
        [
            (PasswordPolicy(require_uppercase=True), "thundering-mongoose", "uppercase"),
            (PasswordPolicy(require_lowercase=True), "THUNDERING-MONGOOSE", "lowercase"),
            (PasswordPolicy(require_digit=True), "thundering-mongoose", "digit"),
            (PasswordPolicy(require_symbol=True), "thunderingmongoose91", "symbol"),
        ],
    )
    def test_optional_composition_rules(
        self, policy: PasswordPolicy, password: str, expected_fragment: str
    ) -> None:
        with pytest.raises(WeakPasswordError) as excinfo:
            policy.validate(password)
        assert any(expected_fragment in f for f in excinfo.value.failures)


class TestLockoutPolicy:
    def test_no_lock_below_the_threshold(self) -> None:
        policy = LockoutPolicy(max_failed_attempts=5)
        assert all(policy.lock_duration(n) == 0 for n in range(5))

    def test_backoff_is_exponential(self) -> None:
        policy = LockoutPolicy(max_failed_attempts=3, base_seconds=60, max_seconds=3600)
        assert policy.lock_duration(3) == 60
        assert policy.lock_duration(4) == 120
        assert policy.lock_duration(5) == 240

    def test_backoff_is_capped(self) -> None:
        # An uncapped lock hands an attacker a denial-of-service primitive against any
        # account whose address they know.
        policy = LockoutPolicy(max_failed_attempts=3, base_seconds=60, max_seconds=900)
        assert policy.lock_duration(50) == 900


class TestInventoryPolicy:
    def test_normalizes_and_deduplicates_preserving_order(self) -> None:
        policy = InventoryPolicy()
        assert policy.normalize_tags(["PCI", "payments", "pci", "  ", "Payments"]) == [
            "pci",
            "payments",
        ]

    @pytest.mark.parametrize("tag", ["has space", "UPPER CASE!", "a", "x" * 50, "-leading"])
    def test_rejects_malformed_tags(self, tag: str) -> None:
        with pytest.raises(ValueError, match="Invalid tag"):
            InventoryPolicy().normalize_tags([tag])

    def test_enforces_tag_count(self) -> None:
        with pytest.raises(ValueError, match="At most"):
            InventoryPolicy(max_tags=3).normalize_tags([f"tag{i}" for i in range(4)])
