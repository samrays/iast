"""The User aggregate: platform identity, lockout state and MFA credentials.

A user is a *platform-wide* identity. Tenant access is expressed by :class:`Membership`,
never by fields on the user, so one person can belong to several organizations without a
duplicate account.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from ..errors import AccountDisabledError, AccountLockedError, InvalidStateError
from ..policies import LockoutPolicy
from ..value_objects import EmailAddress, PasswordHash, new_id


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVITED = "INVITED"
    DISABLED = "DISABLED"


class MfaKind(StrEnum):
    TOTP = "TOTP"
    RECOVERY_CODE = "RECOVERY_CODE"


@dataclass(slots=True)
class MfaCredential:
    """A second factor.

    TOTP secrets are stored encrypted (the ciphertext is produced by an infrastructure
    adapter; the domain only ever holds the opaque string). Recovery codes are stored as
    Argon2 hashes and are single-use.
    """

    user_id: UUID
    kind: MfaKind
    secret_encrypted: str
    confirmed: bool = False
    consumed_at: datetime | None = None
    last_used_at: datetime | None = None
    label: str | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None

    @property
    def is_usable(self) -> bool:
        if self.kind is MfaKind.RECOVERY_CODE:
            return self.consumed_at is None
        return self.confirmed

    def confirm(self, now: datetime) -> None:
        if self.kind is not MfaKind.TOTP:
            raise InvalidStateError("Only a TOTP credential can be confirmed.")
        self.confirmed = True
        self.last_used_at = now

    def consume(self, now: datetime) -> None:
        """Mark a recovery code used. Recovery codes never work twice."""
        if self.kind is not MfaKind.RECOVERY_CODE:
            raise InvalidStateError("Only a recovery code can be consumed.")
        if self.consumed_at is not None:
            raise InvalidStateError("This recovery code has already been used.")
        self.consumed_at = now
        self.last_used_at = now


@dataclass(slots=True)
class User:
    """A person who can sign in."""

    email: EmailAddress
    password_hash: PasswordHash | None = None
    full_name: str = ""
    status: UserStatus = UserStatus.ACTIVE
    is_platform_admin: bool = False
    mfa_enabled: bool = False
    failed_login_count: int = 0
    locked_until: datetime | None = None
    password_changed_at: datetime | None = None
    last_login_at: datetime | None = None
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        self.full_name = (self.full_name or "").strip()[:200]

    # --- state ---------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        return self.status is UserStatus.ACTIVE

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now

    def lock_retry_after(self, now: datetime) -> int:
        if not self.is_locked(now) or self.locked_until is None:
            return 0
        return max(1, int((self.locked_until - now).total_seconds()))

    # --- sign-in -------------------------------------------------------------

    def assert_can_authenticate(self, now: datetime) -> None:
        """Gate checks that run *before* the password is verified.

        Ordering matters: a disabled or locked account must not be told whether the
        password was right, and we must not spend Argon2 time on an account that cannot
        sign in anyway — that would be a cheap CPU-exhaustion vector.
        """
        if self.status is UserStatus.DISABLED:
            raise AccountDisabledError
        if self.is_locked(now):
            raise AccountLockedError(self.lock_retry_after(now))

    def record_failed_login(self, now: datetime, policy: LockoutPolicy) -> None:
        """Count a failure and apply exponential backoff once the threshold is crossed."""
        self.failed_login_count += 1
        duration = policy.lock_duration(self.failed_login_count)
        if duration:
            self.locked_until = now + timedelta(seconds=duration)

    def record_successful_login(self, now: datetime) -> None:
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login_at = now

    # --- credentials ---------------------------------------------------------

    def set_password(self, password_hash: PasswordHash, now: datetime) -> None:
        self.password_hash = password_hash
        self.password_changed_at = now
        self.failed_login_count = 0
        self.locked_until = None
        if self.status is UserStatus.INVITED:
            self.status = UserStatus.ACTIVE

    def enable_mfa(self) -> None:
        self.mfa_enabled = True

    def disable_mfa(self) -> None:
        self.mfa_enabled = False

    # --- lifecycle -----------------------------------------------------------

    def disable(self) -> None:
        if self.is_platform_admin:
            raise InvalidStateError("A platform administrator cannot be disabled here.")
        self.status = UserStatus.DISABLED

    def reactivate(self) -> None:
        self.status = UserStatus.ACTIVE
        self.failed_login_count = 0
        self.locked_until = None

    def rename(self, full_name: str) -> None:
        self.full_name = (full_name or "").strip()[:200]
