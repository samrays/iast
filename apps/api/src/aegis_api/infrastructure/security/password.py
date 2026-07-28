"""Argon2id password hashing."""

from __future__ import annotations

import contextlib

from argon2 import PasswordHasher as _Argon2
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type


class Argon2PasswordHasher:
    """Argon2id with OWASP-recommended parameters.

    Argon2id rather than bcrypt or PBKDF2 because it resists GPU and ASIC attack through
    memory hardness — with 64 MiB per hash, an attacker's parallelism is bounded by memory
    bandwidth rather than by core count.
    """

    #: A precomputed hash of a throwaway value, used to burn equivalent CPU when no user
    #: matches. Verifying against it costs the same as a real verify, so response time does
    #: not distinguish "no such account" from "wrong password" (threat T-07).
    _DUMMY_PASSWORD = "aegis-timing-equalizer"  # noqa: S105 - not a credential

    def __init__(
        self,
        *,
        time_cost: int = 3,
        memory_cost_kib: int = 65_536,
        parallelism: int = 4,
        hash_len: int = 32,
        salt_len: int = 16,
    ) -> None:
        self._hasher = _Argon2(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash(self._DUMMY_PASSWORD)

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        """True when the stored hash used weaker parameters than we now require.

        Hashes are upgraded transparently at the next successful sign-in, so raising the
        cost parameters does not require a password reset campaign.
        """
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    def dummy_verify(self) -> None:
        """Spend the same CPU as a real verification and discard the result."""
        # Discarding the result is the entire point: this call exists to burn CPU.
        with contextlib.suppress(VerifyMismatchError, VerificationError, InvalidHashError):
            self._hasher.verify(self._dummy_hash, "wrong-password")
