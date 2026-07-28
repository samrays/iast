"""Value objects.

Immutable, self-validating, compared by value. Constructing one of these is the only way
to get a valid instance — there is no path that produces an ``EmailAddress`` holding
something that is not an email address.
"""

from __future__ import annotations

import os
import re
import secrets
import time
import unicodedata
import uuid
from dataclasses import dataclass
from typing import ClassVar, Final

from .errors import InvalidEmailError, InvalidSlugError, ValidationError

# --- Identifiers --------------------------------------------------------------------

_LAST_UUID7_MS: list[int] = [0]
_UUID7_COUNTER: list[int] = [0]


def new_id() -> uuid.UUID:
    """Generate a UUIDv7 — time-ordered, which keeps B-tree index inserts sequential.

    Implemented locally rather than pulled from a dependency because the domain layer may
    not import third-party packages (ADR-0002), and because Python's stdlib gained
    ``uuid7`` only in 3.14.

    Layout (RFC 9562):
        48 bits  unix_ts_ms
         4 bits  version (7)
        12 bits  monotonic counter within the millisecond
         2 bits  variant (0b10)
        62 bits  random
    """
    now_ms = int(time.time() * 1000)
    if now_ms == _LAST_UUID7_MS[0]:
        _UUID7_COUNTER[0] = (_UUID7_COUNTER[0] + 1) & 0xFFF
        if _UUID7_COUNTER[0] == 0:
            # Counter wrapped inside a millisecond; borrow from the next one so the
            # ordering guarantee holds.
            now_ms += 1
            _LAST_UUID7_MS[0] = now_ms
    else:
        _LAST_UUID7_MS[0] = now_ms
        _UUID7_COUNTER[0] = secrets.randbelow(0x100)

    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
    value = (
        (now_ms & ((1 << 48) - 1)) << 80
        | 0x7 << 76
        | (_UUID7_COUNTER[0] & 0xFFF) << 64
        | 0b10 << 62
        | rand_b
    )
    return uuid.UUID(int=value)


# --- Email ------------------------------------------------------------------------

# Deliberately pragmatic rather than RFC 5322-complete: reject what is obviously not an
# address, and let delivery verification prove the rest.
_EMAIL_RE: Final = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9]([A-Za-z0-9\-.]{0,251}[A-Za-z0-9])?$")
_MAX_EMAIL_LENGTH: Final = 254


@dataclass(frozen=True, slots=True)
class EmailAddress:
    """A normalized email address.

    Normalization is lowercase plus NFKC. It is applied consistently so that the unique
    index on the users table is the actual uniqueness guarantee, not an approximation.
    """

    value: str

    def __post_init__(self) -> None:
        raw = unicodedata.normalize("NFKC", self.value or "").strip().lower()
        if not raw or len(raw) > _MAX_EMAIL_LENGTH or not _EMAIL_RE.match(raw):
            raise InvalidEmailError(field="email", value=self.value)
        if "." not in raw.split("@", 1)[1]:
            raise InvalidEmailError(field="email", value=self.value)
        object.__setattr__(self, "value", raw)

    @property
    def domain(self) -> str:
        return self.value.split("@", 1)[1]

    @property
    def local_part(self) -> str:
        return self.value.split("@", 1)[0]

    def __str__(self) -> str:
        return self.value


# --- Slug -------------------------------------------------------------------------

_SLUG_RE: Final = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MAX_SLUG_LENGTH: Final = 63
_RESERVED_SLUGS: Final = frozenset(
    {"api", "app", "admin", "www", "auth", "login", "static", "assets", "aegis", "system"}
)


@dataclass(frozen=True, slots=True)
class Slug:
    """A URL-safe identifier used for organizations and applications."""

    value: str

    def __post_init__(self) -> None:
        raw = (self.value or "").strip().lower()
        if not raw or len(raw) > _MAX_SLUG_LENGTH or not _SLUG_RE.match(raw):
            raise InvalidSlugError(field="slug", value=self.value)
        if raw in _RESERVED_SLUGS:
            raise InvalidSlugError(f"{raw!r} is reserved.", field="slug", value=self.value)
        object.__setattr__(self, "value", raw)

    @classmethod
    def from_name(cls, name: str) -> Slug:
        """Derive a slug from a display name, e.g. 'Acme Corp!' -> 'acme-corp'."""
        ascii_name = (
            unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii").lower()
        )
        candidate = re.sub(r"[^a-z0-9]+", "-", ascii_name).strip("-")[:_MAX_SLUG_LENGTH].strip("-")
        if not candidate:
            raise InvalidSlugError("A slug cannot be derived from this name.", field="name")
        if candidate in _RESERVED_SLUGS:
            candidate = f"{candidate}-org"
        return cls(candidate)

    def __str__(self) -> str:
        return self.value


# --- Secrets ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PasswordHash:
    """An opaque password hash.

    Wrapping the string keeps a raw password from being assignable to a field that expects
    a hash — the type system catches the mistake that would otherwise store plaintext.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.startswith("$"):
            raise ValidationError("Not a valid password hash.", field="password_hash")

    def __str__(self) -> str:  # pragma: no cover - defensive
        return "<password-hash>"

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return "<password-hash>"


@dataclass(frozen=True, slots=True)
class TokenHash:
    """SHA-256 hex digest of a high-entropy token.

    Refresh tokens carry 256 bits of entropy, so a slow KDF buys nothing — a plain digest
    is the right tool and keeps refresh lookups cheap (ADR-0006).
    """

    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64 or not all(c in "0123456789abcdef" for c in self.value.lower()):
            raise ValidationError("Not a valid token hash.", field="token_hash")
        object.__setattr__(self, "value", self.value.lower())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ApiKeyPrefix:
    """The public, indexable portion of an API key.

    A key is ``ak_<prefix>.<secret>``. The prefix is stored in the clear and uniquely
    indexed so a lookup costs one index probe; only then is the expensive Argon2 verify of
    the secret performed. Without this split, verifying a key would mean hashing against
    every key in the table.
    """

    value: str

    #: ``ClassVar`` and not ``Final``: dataclasses treat a bare ``Final`` annotation as a
    #: field, which would turn this constant into a required constructor argument.
    LENGTH: ClassVar[int] = 12

    def __post_init__(self) -> None:
        if len(self.value) != self.LENGTH or not self.value.isalnum():
            raise ValidationError("Not a valid API key prefix.", field="prefix")

    def __str__(self) -> str:
        return self.value


# --- Network ----------------------------------------------------------------------


def normalize_recovery_code(raw: str) -> str:
    """Canonical form of an MFA recovery code.

    Codes are displayed grouped (``A3F9K-2QX7M``) because they get written down, but the
    separator, spacing and case are cosmetic. Both hashing at enrolment and verification at
    sign-in go through this function, so a user who types the code without the dash — or in
    lowercase — is still let in. Skipping this on one of the two paths silently breaks every
    recovery code.
    """
    return (raw or "").strip().replace(" ", "").replace("-", "").upper()


@dataclass(frozen=True, slots=True)
class IpAddress:
    """A client IP recorded on sessions and audit events. Never used for authorization."""

    value: str

    def __post_init__(self) -> None:
        raw = (self.value or "").strip()
        if not raw or len(raw) > 45:
            raise ValidationError("Not a valid IP address.", field="ip_address")
        object.__setattr__(self, "value", raw)

    def __str__(self) -> str:
        return self.value
