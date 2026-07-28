"""Domain errors.

These are raised by entities, policies and use cases. The HTTP layer maps them to RFC 9457
problem responses in exactly one place (``interfaces/http/errors.py``); nothing below the
interface layer knows about status codes.
"""

from __future__ import annotations

from typing import Any


class DomainError(Exception):
    """Base class for every error the domain can raise."""

    code: str = "domain_error"
    message: str = "A domain rule was violated."

    def __init__(self, message: str | None = None, **context: Any) -> None:
        self.message = message or self.message
        self.context: dict[str, Any] = context
        super().__init__(self.message)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# --- Validation ---------------------------------------------------------------------


class ValidationError(DomainError):
    code = "validation_error"
    message = "The supplied value is not valid."

    def __init__(self, message: str | None = None, *, field: str | None = None, **context: Any):
        super().__init__(message, field=field, **context)
        self.field = field


class InvalidEmailError(ValidationError):
    code = "invalid_email"
    message = "The email address is not valid."


class InvalidSlugError(ValidationError):
    code = "invalid_slug"
    message = "The slug may contain only lowercase letters, digits and hyphens."


class WeakPasswordError(ValidationError):
    code = "weak_password"
    message = "The password does not satisfy the password policy."

    def __init__(self, failures: list[str]) -> None:
        super().__init__(
            "The password does not satisfy the password policy.",
            field="password",
            failures=failures,
        )
        self.failures = failures


# --- Lifecycle / state --------------------------------------------------------------


class NotFoundError(DomainError):
    code = "not_found"
    message = "The requested resource does not exist."

    def __init__(self, resource: str, identifier: Any = None) -> None:
        super().__init__(f"{resource} not found.", resource=resource, identifier=str(identifier))
        self.resource = resource


class ConflictError(DomainError):
    code = "conflict"
    message = "The resource conflicts with an existing one."


class InvalidStateError(DomainError):
    code = "invalid_state"
    message = "The operation is not permitted in the current state."


# --- Authentication -----------------------------------------------------------------


class AuthenticationError(DomainError):
    """Deliberately generic.

    Distinguishing "unknown user" from "wrong password" is a user-enumeration oracle
    (threat T-07). Every failure path raises this same error with this same message.
    """

    code = "invalid_credentials"
    message = "Invalid credentials."


class AccountLockedError(DomainError):
    code = "account_locked"
    message = "The account is temporarily locked after repeated failed sign-in attempts."

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(retry_after_seconds=retry_after_seconds)
        self.retry_after_seconds = retry_after_seconds


class AccountDisabledError(DomainError):
    code = "account_disabled"
    message = "This account has been disabled."


class MfaRequiredError(DomainError):
    code = "mfa_required"
    message = "Multi-factor authentication is required to complete sign-in."


class InvalidMfaCodeError(DomainError):
    code = "invalid_mfa_code"
    message = "The verification code is not valid."


class TokenError(DomainError):
    code = "invalid_token"
    message = "The token is missing, malformed or expired."


class TokenReuseError(DomainError):
    """A consumed refresh token was presented again.

    Per ADR-0006 this is treated as theft: the whole token family is revoked.
    """

    code = "token_reuse_detected"
    message = "This session has been revoked. Please sign in again."


# --- Authorization ------------------------------------------------------------------


class PermissionDeniedError(DomainError):
    code = "permission_denied"
    message = "You do not have permission to perform this action."

    def __init__(self, required: str | None = None) -> None:
        message = (
            f"This action requires the {required} permission."
            if required
            else PermissionDeniedError.message
        )
        super().__init__(message, required=required)
        self.required = required


class PrivilegeEscalationError(PermissionDeniedError):
    """A principal attempted to grant a permission it does not itself hold (threat T-10)."""

    code = "privilege_escalation"

    def __init__(self, permissions: list[str]) -> None:
        DomainError.__init__(
            self,
            "You cannot grant permissions you do not hold: " + ", ".join(sorted(permissions)),
            permissions=permissions,
        )
        self.required = None
        self.permissions = permissions


# --- Entitlement --------------------------------------------------------------------


class LicenseLimitExceededError(DomainError):
    code = "license_limit_exceeded"
    message = "This action exceeds your licence entitlement."

    def __init__(self, limit_name: str, limit: int) -> None:
        super().__init__(
            f"Your licence permits at most {limit} {limit_name}.",
            limit_name=limit_name,
            limit=limit,
        )


class FeatureNotLicensedError(DomainError):
    """The action is well-formed and authorized, but the tier does not include it."""

    code = "feature_not_licensed"
    message = "This capability is not included in your licence."

    def __init__(self, feature: str) -> None:
        super().__init__(f"{feature} is not included in your licence.", feature=feature)
        self.feature = feature


class RateLimitExceededError(DomainError):
    code = "rate_limited"
    message = "Too many requests."

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(retry_after_seconds=retry_after_seconds)
        self.retry_after_seconds = retry_after_seconds
