"""Value object invariants. Pure — no I/O, no event loop."""

from __future__ import annotations

import uuid

import pytest

from aegis_api.domain.errors import InvalidEmailError, InvalidSlugError, ValidationError
from aegis_api.domain.value_objects import (
    ApiKeyPrefix,
    EmailAddress,
    PasswordHash,
    Slug,
    TokenHash,
    new_id,
)


class TestEmailAddress:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("USER@Example.COM", "user@example.com"),
            ("  spaced@example.com  ", "spaced@example.com"),
            ("first.last+tag@sub.example.co.uk", "first.last+tag@sub.example.co.uk"),
        ],
    )
    def test_normalizes(self, raw: str, expected: str) -> None:
        assert EmailAddress(raw).value == expected

    @pytest.mark.parametrize(
        "raw",
        ["", "   ", "no-at-sign", "@example.com", "user@", "user@localhost", "a b@example.com"],
    )
    def test_rejects_invalid(self, raw: str) -> None:
        with pytest.raises(InvalidEmailError):
            EmailAddress(raw)

    def test_rejects_over_length(self) -> None:
        with pytest.raises(InvalidEmailError):
            EmailAddress("a" * 250 + "@example.com")

    def test_exposes_parts(self) -> None:
        address = EmailAddress("owner@aegis.dev")
        assert address.local_part == "owner"
        assert address.domain == "aegis.dev"
        assert str(address) == "owner@aegis.dev"

    def test_equality_is_by_value(self) -> None:
        assert EmailAddress("A@b.com") == EmailAddress("a@b.com")


class TestSlug:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("Acme Corp!", "acme-corp"),
            ("  Multiple   Spaces  ", "multiple-spaces"),
            ("Ünïcödé Ltd", "unicode-ltd"),
            ("already-a-slug", "already-a-slug"),
        ],
    )
    def test_derives_from_name(self, name: str, expected: str) -> None:
        assert Slug.from_name(name).value == expected

    def test_reserved_names_are_suffixed(self) -> None:
        assert Slug.from_name("Admin").value == "admin-org"

    def test_rejects_reserved_slug_directly(self) -> None:
        with pytest.raises(InvalidSlugError):
            Slug("admin")

    @pytest.mark.parametrize("raw", ["", "-leading", "trailing-", "has space", "a" * 64])
    def test_rejects_invalid(self, raw: str) -> None:
        with pytest.raises(InvalidSlugError):
            Slug(raw)

    def test_normalizes_case_rather_than_rejecting_it(self) -> None:
        # Case is normalized, not refused: a slug read back from a URL or a legacy row
        # should not become unrepresentable just because someone typed a capital.
        assert Slug("Upper").value == "upper"

    def test_rejects_name_with_no_usable_characters(self) -> None:
        with pytest.raises(InvalidSlugError):
            Slug.from_name("!!!")


class TestPasswordHash:
    def test_accepts_a_real_hash_shape(self) -> None:
        assert PasswordHash("$argon2id$v=19$m=65536,t=3,p=4$abc$def").value.startswith("$argon2id")

    def test_rejects_plaintext(self) -> None:
        # The wrapper exists precisely to make "assigned a raw password to a hash field"
        # impossible to do accidentally.
        with pytest.raises(ValidationError):
            PasswordHash("hunter2")

    def test_never_reveals_itself_in_repr(self) -> None:
        hashed = PasswordHash("$argon2id$v=19$m=65536,t=3,p=4$abc$def")
        assert "argon2" not in repr(hashed)
        assert "argon2" not in str(hashed)


class TestTokenHash:
    def test_accepts_sha256_hex(self) -> None:
        assert TokenHash("A" * 64).value == "a" * 64

    @pytest.mark.parametrize("raw", ["", "abc", "z" * 64, "a" * 63])
    def test_rejects_non_digest(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            TokenHash(raw)


class TestApiKeyPrefix:
    def test_accepts_twelve_alphanumerics(self) -> None:
        assert ApiKeyPrefix("abc123DEF456").value == "abc123DEF456"

    @pytest.mark.parametrize("raw", ["short", "toolongtoolong", "has-dash-abc"])
    def test_rejects_invalid(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            ApiKeyPrefix(raw)

    def test_length_is_a_class_constant_not_a_field(self) -> None:
        # A bare ``Final`` annotation would make dataclasses treat this as a constructor
        # argument, which is a real bug this test pins down.
        assert ApiKeyPrefix.LENGTH == 12
        assert ApiKeyPrefix("abc123DEF456").LENGTH == 12


class TestNewId:
    def test_is_a_version_7_uuid(self) -> None:
        assert new_id().version == 7

    def test_is_unique(self) -> None:
        assert len({new_id() for _ in range(1000)}) == 1000

    def test_is_time_ordered(self) -> None:
        # Time ordering is what keeps primary-key index inserts sequential rather than
        # scattering them across the B-tree.
        ids = [new_id() for _ in range(500)]
        assert ids == sorted(ids, key=lambda value: value.int)

    def test_is_a_valid_uuid_round_trip(self) -> None:
        value = new_id()
        assert uuid.UUID(str(value)) == value
