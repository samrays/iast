"""Security policies expressed as pure, configurable domain objects.

They live in the domain rather than in configuration parsing so that they can be unit
tested exhaustively and so that a use case can reason about them without reading settings.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Final

from .errors import WeakPasswordError

#: Passwords that appear constantly in breach corpora. This is a floor, not a substitute
#: for the k-anonymity breach check wired in ``infrastructure/security``; the point is that
#: the domain refuses the worst inputs even with every external service unavailable.
_COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "letmein",
        "welcome",
        "welcome1",
        "admin",
        "administrator",
        "iloveyou",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "changeme",
        "secret",
        "abc123",
        "trustno1",
        "master",
        "starwars",
        "aegis",
        "aegis123",
    }
)

_SEQUENTIAL: Final = ("abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiop", "asdfghjkl")


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Composition and quality rules for user passwords.

    The design follows NIST SP 800-63B: length is the dominant factor, arbitrary
    composition rules are weak, and blocking known-bad passwords matters more than
    demanding a symbol. Character-class requirements are configurable but default off,
    with a longer minimum length instead.
    """

    min_length: int = 12
    max_length: int = 256
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    forbid_common: bool = True
    forbid_sequences: bool = True
    #: Minimum distinct characters — catches "aaaaaaaaaaaa" passing a length check.
    min_unique_characters: int = 6

    def validate(self, password: str, *, context: tuple[str, ...] = ()) -> None:
        """Raise :class:`WeakPasswordError` listing every failure, not just the first.

        Reporting all failures at once avoids the frustrating loop where a user fixes one
        rule only to be told about the next.

        ``context`` carries values the password must not contain — the user's email local
        part, the organization name — because those are the first things an attacker tries.
        """
        failures: list[str] = []
        normalized = unicodedata.normalize("NFKC", password or "")

        if len(normalized) < self.min_length:
            failures.append(f"must be at least {self.min_length} characters")
        if len(normalized) > self.max_length:
            failures.append(f"must be at most {self.max_length} characters")
        if self.require_uppercase and not any(c.isupper() for c in normalized):
            failures.append("must contain an uppercase letter")
        if self.require_lowercase and not any(c.islower() for c in normalized):
            failures.append("must contain a lowercase letter")
        if self.require_digit and not any(c.isdigit() for c in normalized):
            failures.append("must contain a digit")
        if self.require_symbol and not any(not c.isalnum() for c in normalized):
            failures.append("must contain a symbol")

        lowered = normalized.lower()
        if self.forbid_common and lowered in _COMMON_PASSWORDS:
            failures.append("is among the most commonly used passwords")
        if self.forbid_sequences and self._has_sequence(lowered):
            failures.append("must not contain a long keyboard or alphabet sequence")
        if len(set(normalized)) < min(self.min_unique_characters, len(normalized) or 1):
            failures.append(
                f"must contain at least {self.min_unique_characters} distinct characters"
            )

        for item in context:
            token = (item or "").strip().lower()
            if len(token) >= 4 and token in lowered:
                failures.append("must not contain your name, email address or organization name")
                break

        if failures:
            raise WeakPasswordError(failures)

    @staticmethod
    def _has_sequence(value: str, length: int = 5) -> bool:
        for source in _SEQUENTIAL:
            for start in range(len(source) - length + 1):
                run = source[start : start + length]
                if run in value or run[::-1] in value:
                    return True
        return False


@dataclass(frozen=True, slots=True)
class LockoutPolicy:
    """Throttling for repeated failed sign-in attempts (threat T-07).

    Exponential backoff rather than a permanent lock: a permanent lock hands an attacker a
    denial-of-service primitive against any account whose email address they know.
    """

    max_failed_attempts: int = 5
    base_seconds: int = 60
    max_seconds: int = 3600
    #: Failures older than this no longer count toward the threshold.
    decay_seconds: int = 900

    def lock_duration(self, failed_count: int) -> int:
        """Seconds to lock after ``failed_count`` consecutive failures."""
        if failed_count < self.max_failed_attempts:
            return 0
        excess = failed_count - self.max_failed_attempts
        return int(min(self.base_seconds * (2**excess), self.max_seconds))


@dataclass(frozen=True, slots=True)
class TokenPolicy:
    """Lifetimes and rotation behaviour for the token pair described in ADR-0006."""

    access_ttl_seconds: int = 900
    refresh_ttl_seconds: int = 2_592_000
    mfa_challenge_ttl_seconds: int = 300
    #: A rotated token stays acceptable for this long so two browser tabs refreshing at the
    #: same moment do not look like theft. Outside the window, reuse revokes the family.
    rotation_grace_seconds: int = 10
    #: Maximum concurrent active sessions per user; the oldest is revoked beyond this.
    max_sessions_per_user: int = 10


@dataclass(frozen=True, slots=True)
class MfaPolicy:
    """TOTP parameters and enrolment rules."""

    digits: int = 6
    period_seconds: int = 30
    #: Accepted clock drift in periods, either direction. One period (±30 s) is the
    #: standard trade-off between usability and the size of the acceptance window.
    valid_window: int = 1
    recovery_code_count: int = 10
    recovery_code_bytes: int = 10
    require_for_privileged_roles: bool = False


_ALLOWED_TAG: Final = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,38}[a-z0-9]$")


@dataclass(frozen=True, slots=True)
class InventoryPolicy:
    """Constraints on application inventory input."""

    max_tags: int = 20
    max_name_length: int = 120
    reserved_names: frozenset[str] = field(default_factory=frozenset)

    def normalize_tags(self, tags: list[str]) -> list[str]:
        """Lowercase, de-duplicate and validate tags, preserving first-seen order."""
        seen: dict[str, None] = {}
        for tag in tags:
            candidate = (tag or "").strip().lower()
            if not candidate:
                continue
            if not _ALLOWED_TAG.match(candidate):
                raise ValueError(
                    f"Invalid tag {tag!r}: use 2-40 lowercase alphanumerics, "
                    "dot, dash or underscore."
                )
            seen.setdefault(candidate, None)
        if len(seen) > self.max_tags:
            raise ValueError(f"At most {self.max_tags} tags are allowed.")
        return list(seen)
