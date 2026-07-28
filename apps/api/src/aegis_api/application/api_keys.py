"""API key issuance and revocation.

Keys are the credential CI pipelines and agent bootstraps use. Format is
``ak_<prefix>.<secret>``: the prefix is indexed and public, the secret is Argon2-hashed and
returned exactly once.
"""

from __future__ import annotations

import secrets
import string
from datetime import timedelta
from uuid import UUID

from ..domain.entities import ApiKey
from ..domain.entities.audit import AuditAction
from ..domain.errors import NotFoundError, ValidationError
from ..domain.permissions import Permission
from ..domain.ports import Clock, PasswordHasher, UnitOfWork
from ..domain.value_objects import ApiKeyPrefix
from .audit_recorder import AuditRecorder
from .context import Principal
from .dto import ApiKeyIssued, ApiKeySummary
from .rbac import parse_permissions

_ALPHABET = string.ascii_letters + string.digits
#: 43 characters of base62 is ~256 bits — the same strength as the refresh token.
_SECRET_LENGTH = 43
_MAX_TTL_DAYS = 730


def _summary(api_key: ApiKey) -> ApiKeySummary:
    return ApiKeySummary(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix.value,
        permissions=sorted(p.value for p in api_key.permissions),
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        revoked_at=api_key.revoked_at,
    )


class ListApiKeys:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal) -> list[ApiKeySummary]:
        principal.require(Permission.SETTINGS_WRITE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            return [_summary(k) for k in await uow.api_keys.list_all()]


class CreateApiKey:
    """Issue a key whose permissions are a subset of the caller's own.

    Without the subset rule an API key would be a privilege-escalation primitive: mint a
    key with permissions you lack, then authenticate as the key.
    """

    def __init__(self, uow: UnitOfWork, clock: Clock, hasher: PasswordHasher) -> None:
        self._uow = uow
        self._clock = clock
        self._hasher = hasher

    async def execute(
        self,
        *,
        principal: Principal,
        name: str,
        permissions: list[str],
        expires_in_days: int | None,
    ) -> ApiKeyIssued:
        principal.require(Permission.SETTINGS_WRITE)
        parsed = parse_permissions(permissions)
        if not parsed:
            raise ValidationError(
                "An API key must carry at least one permission.", field="permissions"
            )
        principal.assert_can_grant(parsed)

        if expires_in_days is not None and not 1 <= expires_in_days <= _MAX_TTL_DAYS:
            raise ValidationError(
                f"Expiry must be between 1 and {_MAX_TTL_DAYS} days.", field="expires_in_days"
            )

        now = self._clock.now()
        prefix = ApiKeyPrefix(
            "".join(secrets.choice(_ALPHABET) for _ in range(ApiKeyPrefix.LENGTH))
        )
        secret = "".join(secrets.choice(_ALPHABET) for _ in range(_SECRET_LENGTH))

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            api_key = ApiKey(
                organization_id=principal.organization_id,
                name=name,
                prefix=prefix,
                secret_hash=self._hasher.hash(secret),
                permissions=parsed,
                created_by=principal.user_id,
                expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
                created_at=now,
            )
            await uow.api_keys.add(api_key)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.API_KEY_CREATED.value,
                resource_type="api_key",
                resource_id=api_key.id,
                metadata={
                    "name": api_key.name,
                    "prefix": prefix.value,
                    "permissions": sorted(p.value for p in parsed),
                    "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                },
            )
            await uow.commit()

            return ApiKeyIssued(summary=_summary(api_key), plaintext_key=f"ak_{prefix}.{secret}")


class RevokeApiKey:
    def __init__(self, uow: UnitOfWork, clock: Clock) -> None:
        self._uow = uow
        self._clock = clock

    async def execute(self, *, principal: Principal, api_key_id: UUID) -> None:
        principal.require(Permission.SETTINGS_WRITE)
        now = self._clock.now()
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            api_key = await uow.api_keys.get(api_key_id)
            if api_key is None:
                raise NotFoundError("ApiKey", api_key_id)

            api_key.revoke(now)
            await uow.api_keys.update(api_key)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.API_KEY_REVOKED.value,
                resource_type="api_key",
                resource_id=api_key.id,
                metadata={"name": api_key.name, "prefix": api_key.prefix.value},
            )
            await uow.commit()
