"""Multi-factor authentication enrolment and management."""

from __future__ import annotations

import secrets
import string

from ..domain.entities import MfaCredential, MfaKind
from ..domain.entities.audit import AuditAction
from ..domain.errors import (
    AuthenticationError,
    InvalidMfaCodeError,
    InvalidStateError,
    NotFoundError,
)
from ..domain.policies import MfaPolicy
from ..domain.ports import SecretCipher, UnitOfWork
from ..domain.value_objects import normalize_recovery_code
from .audit_recorder import AuditRecorder
from .auth import AuthDependencies
from .context import Principal
from .dto import MfaEnrolmentResult

_RECOVERY_ALPHABET = string.ascii_uppercase + string.digits


def _generate_recovery_code() -> str:
    """A 10-character code in two readable groups, e.g. ``A3F9K-2QX7M``.

    Uppercase alphanumerics only: these get written down and typed back in, so the format
    optimizes for transcription rather than density.
    """
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


class EnrolMfa:
    """Begin TOTP enrolment.

    The secret and recovery codes are returned exactly once. They are stored encrypted
    (TOTP seed) and Argon2-hashed (recovery codes) respectively, so neither can be read
    back out of the database.
    """

    def __init__(
        self,
        uow: UnitOfWork,
        deps: AuthDependencies,
        cipher: SecretCipher,
        policy: MfaPolicy,
        *,
        issuer: str,
    ) -> None:
        self._uow = uow
        self._deps = deps
        self._cipher = cipher
        self._policy = policy
        self._issuer = issuer

    async def execute(self, *, principal: Principal, password: str) -> MfaEnrolmentResult:
        # Re-authentication before a security-setting change: an unattended session must
        # not be enough to swap someone's second factor.
        if principal.user_id is None:
            raise InvalidStateError("Only a user principal can enrol a second factor.")

        async with self._uow as uow:
            user = await uow.users.get(principal.user_id)
            if user is None or user.password_hash is None:
                raise NotFoundError("User", principal.user_id)
            if not self._deps.hasher.verify(password, user.password_hash.value):
                raise AuthenticationError("The password is incorrect.")
            if user.mfa_enabled:
                raise InvalidStateError(
                    "Multi-factor authentication is already enabled. Disable it first to re-enrol."
                )

            # Discard any unconfirmed attempt so a stale QR code cannot be used later.
            await uow.mfa_credentials.delete_for_user(user.id)

            secret = self._deps.totp.generate_secret()
            credential = MfaCredential(
                user_id=user.id,
                kind=MfaKind.TOTP,
                secret_encrypted=self._cipher.encrypt(secret),
                confirmed=False,
            )
            await uow.mfa_credentials.add(credential)

            plaintext_codes = [
                _generate_recovery_code() for _ in range(self._policy.recovery_code_count)
            ]
            await uow.mfa_credentials.add_many(
                [
                    MfaCredential(
                        user_id=user.id,
                        kind=MfaKind.RECOVERY_CODE,
                        secret_encrypted=self._deps.hasher.hash(normalize_recovery_code(code)),
                    )
                    for code in plaintext_codes
                ]
            )
            await uow.commit()

            return MfaEnrolmentResult(
                secret=secret,
                provisioning_uri=self._deps.totp.provisioning_uri(
                    secret, account=user.email.value, issuer=self._issuer
                ),
                recovery_codes=plaintext_codes,
            )


class ConfirmMfa:
    """Prove the authenticator app works before MFA is switched on.

    Confirming with a live code is what prevents a user from locking themselves out with a
    mis-scanned QR code.
    """

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies, cipher: SecretCipher) -> None:
        self._uow = uow
        self._deps = deps
        self._cipher = cipher

    async def execute(self, *, principal: Principal, code: str) -> None:
        now = self._deps.clock.now()
        if principal.user_id is None:
            raise InvalidStateError("Only a user principal can confirm a second factor.")

        async with self._uow as uow:
            user = await uow.users.get(principal.user_id)
            if user is None:
                raise NotFoundError("User", principal.user_id)

            credential = await uow.mfa_credentials.get_totp(user.id, confirmed=False)
            if credential is None:
                raise InvalidStateError("There is no pending enrolment to confirm.")

            secret = self._cipher.decrypt(credential.secret_encrypted)
            if not self._deps.totp.verify(secret, (code or "").strip(), now=now):
                raise InvalidMfaCodeError

            credential.confirm(now)
            await uow.mfa_credentials.update(credential)
            user.enable_mfa()
            await uow.users.update(user)

            await uow.bind_tenant(principal.organization_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.MFA_ENROLLED.value,
                resource_type="user",
                resource_id=user.id,
            )
            await uow.commit()


class DisableMfa:
    """Turn MFA off. Requires the password, and removes every stored factor."""

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies, policy: MfaPolicy) -> None:
        self._uow = uow
        self._deps = deps
        self._policy = policy

    async def execute(self, *, principal: Principal, password: str) -> None:
        if principal.user_id is None:
            raise InvalidStateError("Only a user principal can disable a second factor.")

        async with self._uow as uow:
            user = await uow.users.get(principal.user_id)
            if user is None or user.password_hash is None:
                raise NotFoundError("User", principal.user_id)
            if not self._deps.hasher.verify(password, user.password_hash.value):
                raise AuthenticationError("The password is incorrect.")
            if not user.mfa_enabled:
                raise InvalidStateError("Multi-factor authentication is not enabled.")

            from ..domain.permissions import is_privileged

            if self._policy.require_for_privileged_roles and is_privileged(principal.permissions):
                raise InvalidStateError(
                    "This organization requires multi-factor authentication for privileged roles."
                )

            await uow.mfa_credentials.delete_for_user(user.id)
            user.disable_mfa()
            await uow.users.update(user)

            await uow.bind_tenant(principal.organization_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.MFA_DISABLED.value,
                resource_type="user",
                resource_id=user.id,
            )
            await uow.commit()
