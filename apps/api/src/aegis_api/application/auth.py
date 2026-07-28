"""Authentication use cases.

Registration, sign-in, MFA challenge completion, refresh rotation, logout and password
change. The token behaviour implemented here is specified in ADR-0006; the anti-enumeration
and lockout behaviour is threat T-07.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from ..domain.entities import (
    ActorType,
    AuditOutcome,
    License,
    LicenseTier,
    Membership,
    Organization,
    Role,
    Session,
    User,
)
from ..domain.entities.audit import AuditAction
from ..domain.errors import (
    AuthenticationError,
    ConflictError,
    InvalidMfaCodeError,
    InvalidStateError,
    NotFoundError,
    TokenError,
    TokenReuseError,
    ValidationError,
)
from ..domain.permissions import (
    SYSTEM_ROLE_DESCRIPTIONS,
    SYSTEM_ROLE_PERMISSIONS,
    Permission,
    SystemRole,
)
from ..domain.policies import LockoutPolicy, PasswordPolicy, TokenPolicy
from ..domain.ports import (
    AccessTokenCodec,
    Clock,
    PasswordHasher,
    SecretCipher,
    TokenGenerator,
    TotpService,
    UnitOfWork,
)
from ..domain.value_objects import (
    EmailAddress,
    PasswordHash,
    Slug,
    normalize_recovery_code,
)
from .audit_recorder import AuditRecorder
from .context import Principal, RequestContext
from .dto import (
    AuthenticationResult,
    CurrentPrincipal,
    MfaChallenge,
    OrganizationSummary,
    RegistrationResult,
    RoleSummary,
    TokenPair,
)

USER_AUDIENCE = "aegis:user"
AGENT_AUDIENCE = "aegis:agent"
MFA_CHALLENGE_AUDIENCE = "aegis:mfa_challenge"


@dataclass(frozen=True, slots=True)
class AuthDependencies:
    """Everything the authentication use cases need, injected as ports."""

    clock: Clock
    hasher: PasswordHasher
    tokens: TokenGenerator
    codec: AccessTokenCodec
    totp: TotpService
    cipher: SecretCipher
    password_policy: PasswordPolicy
    lockout_policy: LockoutPolicy
    token_policy: TokenPolicy


def _role_summary(role: Role) -> RoleSummary:
    return RoleSummary(
        id=role.id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=sorted(p.value for p in role.permissions),
    )


def _org_summary(organization: Organization) -> OrganizationSummary:
    return OrganizationSummary(
        id=organization.id,
        name=organization.name,
        slug=organization.slug.value,
        status=organization.status.value,
    )


def build_system_roles(organization_id: UUID) -> list[Role]:
    """The five roles seeded into every new organization."""
    return [
        Role.system(
            organization_id,
            role,
            SYSTEM_ROLE_PERMISSIONS[role],
            SYSTEM_ROLE_DESCRIPTIONS[role],
        )
        for role in SystemRole
    ]


class SessionIssuer:
    """Creates the token pair and its backing session.

    Shared by sign-in, MFA completion and refresh so the three paths cannot drift apart —
    a divergence there is exactly how session-fixation bugs appear.
    """

    def __init__(self, deps: AuthDependencies) -> None:
        self._deps = deps

    async def issue(
        self,
        uow: UnitOfWork,
        *,
        user: User,
        membership: Membership,
        mfa_satisfied: bool,
        context: RequestContext,
        now: datetime,
    ) -> TokenPair:
        policy = self._deps.token_policy

        await self._enforce_session_cap(uow, user_id=user.id, now=now)

        refresh_token, refresh_hash = self._deps.tokens.generate()
        session = Session.start(
            user_id=user.id,
            organization_id=membership.organization_id,
            refresh_token_hash=refresh_hash,
            ttl_seconds=policy.refresh_ttl_seconds,
            now=now,
            user_agent=context.user_agent,
            ip_address=context.ip_address,
        )
        await uow.sessions.add(session)

        access_token, access_expires = self._deps.codec.issue(
            subject=user.id,
            organization_id=membership.organization_id,
            session_id=session.id,
            permissions=frozenset(p.value for p in membership.permissions),
            mfa_satisfied=mfa_satisfied,
            ttl_seconds=policy.access_ttl_seconds,
            now=now,
        )
        return TokenPair(
            access_token=access_token,
            access_token_expires_at=access_expires,
            refresh_token=refresh_token,
            refresh_token_expires_at=session.expires_at,
            session_id=session.id,
        )

    async def _enforce_session_cap(self, uow: UnitOfWork, *, user_id: UUID, now: datetime) -> None:
        """Keep the number of live sessions bounded.

        An unbounded session table is both a storage problem and a security one: every
        stale session is a credential someone might still hold.
        """
        cap = self._deps.token_policy.max_sessions_per_user
        active = await uow.sessions.list_active_for_user(user_id, now=now)
        if len(active) < cap:
            return
        overflow = sorted(active, key=lambda s: s.created_at or now)[: len(active) - cap + 1]
        for session in overflow:
            session.revoke(now, "session_cap_exceeded")
            await uow.sessions.update(session)


class RegisterOrganization:
    """Create an organization with its first Owner.

    This is the only path that creates a tenant from an unauthenticated request, and it is
    gated by ``allow_self_service_signup``.
    """

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies, *, allow_signup: bool) -> None:
        self._uow = uow
        self._deps = deps
        self._allow_signup = allow_signup

    async def execute(
        self,
        *,
        organization_name: str,
        email: str,
        password: str,
        full_name: str,
        context: RequestContext,
        tier: LicenseTier = LicenseTier.TRIAL,
    ) -> RegistrationResult:
        if not self._allow_signup:
            raise InvalidStateError("Self-service signup is disabled on this deployment.")

        now = self._deps.clock.now()
        address = EmailAddress(email)
        self._deps.password_policy.validate(
            password, context=(address.local_part, organization_name, full_name)
        )

        async with self._uow as uow:
            if await uow.users.email_exists(address):
                # Registration is not an enumeration oracle worth protecting: the caller is
                # creating an account, and a generic error would leave them stuck. We do,
                # however, decline to say whether the address is in *this* organization.
                raise ConflictError("An account already exists for this email address.")

            slug = await self._allocate_slug(uow, organization_name)
            organization = Organization(name=organization_name.strip(), slug=slug)
            await uow.organizations.add(organization)
            # Bind before touching any tenant-owned table: the licence row is subject to
            # row-level security, and its WITH CHECK clause reads the tenant GUC.
            await uow.bind_tenant(organization.id)
            await uow.licenses.add(License.for_tier(organization.id, tier))

            roles = await uow.roles.add_many(build_system_roles(organization.id))
            owner_role = next(r for r in roles if r.name == SystemRole.OWNER.value)

            user = User(
                email=address,
                password_hash=PasswordHash(self._deps.hasher.hash(password)),
                full_name=full_name,
                password_changed_at=now,
            )
            await uow.users.add(user)

            membership = Membership(
                organization_id=organization.id,
                user_id=user.id,
                roles=(owner_role,),
                joined_at=now,
            )
            await uow.memberships.add(membership)

            principal = Principal.for_membership(
                membership,
                session_id=None,
                label=address.value,
                mfa_satisfied=False,
                context=context,
            )
            recorder = AuditRecorder(uow.audit)
            await recorder.record(
                principal=principal,
                action=AuditAction.ORGANIZATION_CREATED.value,
                resource_type="organization",
                resource_id=organization.id,
                metadata={"slug": slug.value, "tier": tier.value},
            )

            tokens = await SessionIssuer(self._deps).issue(
                uow,
                user=user,
                membership=membership,
                mfa_satisfied=False,
                context=context,
                now=now,
            )
            await recorder.record(
                principal=principal,
                action=AuditAction.LOGIN_SUCCEEDED.value,
                resource_type="user",
                resource_id=user.id,
                metadata={"via": "registration"},
            )
            await uow.commit()

            return RegistrationResult(
                organization=_org_summary(organization),
                user_id=user.id,
                email=address.value,
                tokens=tokens,
            )

    @staticmethod
    async def _allocate_slug(uow: UnitOfWork, name: str) -> Slug:
        """Derive a slug, appending a counter until it is free."""
        base = Slug.from_name(name)
        if not await uow.organizations.slug_exists(base):
            return base
        for suffix in range(2, 100):
            candidate = Slug(f"{base.value[:56]}-{suffix}")
            if not await uow.organizations.slug_exists(candidate):
                return candidate
        raise ConflictError("Unable to allocate an organization slug; please choose another name.")


class AuthenticateUser:
    """Verify a password and either issue tokens or demand a second factor."""

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(
        self,
        *,
        email: str,
        password: str,
        organization_slug: str | None,
        context: RequestContext,
    ) -> AuthenticationResult:
        now = self._deps.clock.now()

        try:
            address = EmailAddress(email)
        except Exception:
            # A malformed address is a failed sign-in, not a validation error — otherwise
            # the response shape distinguishes "no such user" from "bad input".
            self._deps.hasher.dummy_verify()
            raise AuthenticationError from None

        async with self._uow as uow:
            user = await uow.users.get_by_email(address)
            if user is None or user.password_hash is None:
                # Spend the same CPU as a real verify so response time reveals nothing.
                self._deps.hasher.dummy_verify()
                raise AuthenticationError

            user.assert_can_authenticate(now)

            if not self._deps.hasher.verify(password, user.password_hash.value):
                user.record_failed_login(now, self._deps.lockout_policy)
                await uow.users.update(user)
                await self._audit_failure(uow, user, organization_slug, context, now)
                await uow.commit()
                raise AuthenticationError

            if self._deps.hasher.needs_rehash(user.password_hash.value):
                # Transparently upgrade the hash now that we hold the plaintext.
                user.password_hash = PasswordHash(self._deps.hasher.hash(password))

            membership, organization = await self._resolve_membership(uow, user, organization_slug)
            await uow.bind_tenant(organization.id)

            user.record_successful_login(now)
            await uow.users.update(user)
            recorder = AuditRecorder(uow.audit)

            if user.mfa_enabled:
                challenge = self._deps.codec.issue_challenge(
                    subject=user.id,
                    organization_id=organization.id,
                    ttl_seconds=self._deps.token_policy.mfa_challenge_ttl_seconds,
                    now=now,
                    purpose="mfa",
                )
                await uow.commit()
                return AuthenticationResult(
                    challenge=MfaChallenge(
                        challenge_token=challenge,
                        expires_at=now
                        + timedelta(seconds=self._deps.token_policy.mfa_challenge_ttl_seconds),
                        methods=["totp", "recovery_code"],
                    )
                )

            principal = Principal.for_membership(
                membership,
                session_id=None,
                label=address.value,
                mfa_satisfied=False,
                context=context,
            )
            tokens = await SessionIssuer(self._deps).issue(
                uow,
                user=user,
                membership=membership,
                mfa_satisfied=False,
                context=context,
                now=now,
            )
            await recorder.record(
                principal=principal,
                action=AuditAction.LOGIN_SUCCEEDED.value,
                resource_type="user",
                resource_id=user.id,
            )
            await uow.commit()
            return AuthenticationResult(tokens=tokens)

    async def _resolve_membership(
        self, uow: UnitOfWork, user: User, organization_slug: str | None
    ) -> tuple[Membership, Organization]:
        """Pick the tenant this sign-in is for.

        A user may belong to several organizations. With one membership the choice is
        obvious; with several the caller must say which, because silently choosing for them
        would place a session in an organization they did not intend.
        """
        if organization_slug:
            organization = await uow.organizations.get_by_slug(Slug(organization_slug))
            if organization is None or not organization.is_active:
                raise AuthenticationError
            await uow.bind_tenant(organization.id)
            membership = await uow.memberships.get_for_user(user.id)
            if membership is None or not membership.is_active:
                raise AuthenticationError
            return membership, organization

        candidates = await uow.find_active_organizations_for_user(user.id)
        if not candidates:
            raise AuthenticationError
        if len(candidates) > 1:
            raise ValidationError(
                "Specify which organization to sign in to.",
                field="organization_slug",
                organizations=[o.slug.value for o in candidates],
            )
        organization = candidates[0]
        await uow.bind_tenant(organization.id)
        membership = await uow.memberships.get_for_user(user.id)
        if membership is None or not membership.is_active:
            raise AuthenticationError
        return membership, organization

    async def _audit_failure(
        self,
        uow: UnitOfWork,
        user: User,
        organization_slug: str | None,
        context: RequestContext,
        now: datetime,
    ) -> None:
        """Record the failure against the tenant, when one can be determined."""
        organizations = await uow.find_active_organizations_for_user(user.id)
        if organization_slug:
            organizations = [o for o in organizations if o.slug.value == organization_slug]
        if len(organizations) != 1:
            return
        organization = organizations[0]
        await uow.bind_tenant(organization.id)
        recorder = AuditRecorder(uow.audit)
        await recorder.record(
            principal=None,
            organization_id=organization.id,
            actor_type=ActorType.USER,
            actor_user_id=user.id,
            actor_label=user.email.value,
            action=AuditAction.LOGIN_FAILED.value,
            resource_type="user",
            resource_id=user.id,
            outcome=AuditOutcome.FAILURE,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"failed_login_count": user.failed_login_count},
        )
        if user.is_locked(now):
            await recorder.record(
                principal=None,
                organization_id=organization.id,
                actor_type=ActorType.USER,
                actor_user_id=user.id,
                actor_label=user.email.value,
                action=AuditAction.ACCOUNT_LOCKED.value,
                resource_type="user",
                resource_id=user.id,
                outcome=AuditOutcome.FAILURE,
                ip_address=context.ip_address,
                metadata={"retry_after_seconds": user.lock_retry_after(now)},
            )


class CompleteMfaChallenge:
    """Exchange a challenge token plus a TOTP or recovery code for a session."""

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(
        self, *, challenge_token: str, code: str, context: RequestContext
    ) -> TokenPair:
        now = self._deps.clock.now()
        claims = self._deps.codec.decode(challenge_token, audience=MFA_CHALLENGE_AUDIENCE)
        if claims.get("purpose") != "mfa":
            raise TokenError("This token cannot be used to complete sign-in.")

        user_id = UUID(str(claims["sub"]))
        organization_id = UUID(str(claims["org"]))

        async with self._uow as uow:
            user = await uow.users.get(user_id)
            if user is None or not user.is_active:
                raise AuthenticationError
            user.assert_can_authenticate(now)

            await uow.bind_tenant(organization_id)
            membership = await uow.memberships.get_for_user(user_id)
            if membership is None or not membership.is_active:
                raise AuthenticationError

            recorder = AuditRecorder(uow.audit)
            if not await self._verify_code(uow, user_id, code, now):
                user.record_failed_login(now, self._deps.lockout_policy)
                await uow.users.update(user)
                await recorder.record(
                    principal=None,
                    organization_id=organization_id,
                    actor_type=ActorType.USER,
                    actor_user_id=user_id,
                    actor_label=user.email.value,
                    action=AuditAction.MFA_CHALLENGE_FAILED.value,
                    resource_type="user",
                    resource_id=user_id,
                    outcome=AuditOutcome.FAILURE,
                    ip_address=context.ip_address,
                )
                await uow.commit()
                raise InvalidMfaCodeError

            user.record_successful_login(now)
            await uow.users.update(user)

            principal = Principal.for_membership(
                membership,
                session_id=None,
                label=user.email.value,
                mfa_satisfied=True,
                context=context,
            )
            tokens = await SessionIssuer(self._deps).issue(
                uow,
                user=user,
                membership=membership,
                mfa_satisfied=True,
                context=context,
                now=now,
            )
            await recorder.record(
                principal=principal,
                action=AuditAction.LOGIN_SUCCEEDED.value,
                resource_type="user",
                resource_id=user_id,
                metadata={"mfa": True},
            )
            await uow.commit()
            return tokens

    async def _verify_code(self, uow: UnitOfWork, user_id: UUID, code: str, now: datetime) -> bool:
        candidate = (code or "").strip().replace(" ", "")
        if not candidate:
            return False

        totp = await uow.mfa_credentials.get_totp(user_id, confirmed=True)
        if totp is not None:
            secret = self._deps.cipher.decrypt(totp.secret_encrypted)
            if self._deps.totp.verify(secret, candidate, now=now):
                totp.last_used_at = now
                await uow.mfa_credentials.update(totp)
                return True

        for recovery in await uow.mfa_credentials.list_recovery_codes(user_id):
            if recovery.is_usable and self._deps.hasher.verify(
                normalize_recovery_code(candidate), recovery.secret_encrypted
            ):
                recovery.consume(now)
                await uow.mfa_credentials.update(recovery)
                return True
        return False


class RefreshSession:
    """Rotate a refresh token, detecting reuse (ADR-0006)."""

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(self, *, refresh_token: str, context: RequestContext) -> TokenPair:
        now = self._deps.clock.now()
        token_hash = self._deps.tokens.hash(refresh_token)

        async with self._uow as uow:
            session = await uow.sessions.get_by_token_hash(token_hash)
            if session is None:
                raise TokenError("This refresh token is not recognized.")

            if session.revoked_at is not None:
                raise TokenReuseError

            if session.is_rotated:
                if session.is_within_rotation_grace(
                    now, self._deps.token_policy.rotation_grace_seconds
                ):
                    # Two tabs refreshed at once. Hand back a fresh pair from the successor
                    # rather than punishing a legitimate race.
                    return await self._reissue_from_successor(uow, session, context, now)
                await self._handle_reuse(uow, session, context, now)
                raise TokenReuseError

            if session.is_expired(now):
                raise TokenError("This session has expired. Please sign in again.")

            user = await uow.users.get(session.user_id)
            if user is None or not user.is_active:
                raise AuthenticationError
            user.assert_can_authenticate(now)

            await uow.bind_tenant(session.organization_id)
            membership = await uow.memberships.get_for_user(session.user_id)
            if membership is None or not membership.is_active:
                # Access was revoked while the session was alive. Kill it now rather than
                # waiting for the refresh window to close.
                await uow.sessions.revoke_family(
                    session.family_id, now=now, reason="membership_revoked"
                )
                await uow.commit()
                raise AuthenticationError

            new_token, new_hash = self._deps.tokens.generate()
            successor = session.rotate(
                refresh_token_hash=new_hash,
                now=now,
                absolute_expiry=session.expires_at,
                user_agent=context.user_agent,
                ip_address=context.ip_address,
            )
            await uow.sessions.update(session)
            await uow.sessions.add(successor)

            access_token, access_expires = self._deps.codec.issue(
                subject=user.id,
                organization_id=membership.organization_id,
                session_id=successor.id,
                permissions=frozenset(p.value for p in membership.permissions),
                mfa_satisfied=user.mfa_enabled,
                ttl_seconds=self._deps.token_policy.access_ttl_seconds,
                now=now,
            )
            await uow.commit()

            return TokenPair(
                access_token=access_token,
                access_token_expires_at=access_expires,
                refresh_token=new_token,
                refresh_token_expires_at=successor.expires_at,
                session_id=successor.id,
            )

    async def _reissue_from_successor(
        self, uow: UnitOfWork, session: Session, context: RequestContext, now: datetime
    ) -> TokenPair:
        """Within the grace window, mint a new access token bound to the live successor.

        The refresh token is not re-rotated: the successor already holds the current one,
        and the racing tab will pick it up from the cookie.
        """
        if session.replaced_by_id is None:  # pragma: no cover - defensive
            raise TokenError("This session has been superseded.")

        user = await uow.users.get(session.user_id)
        if user is None or not user.is_active:
            raise AuthenticationError
        await uow.bind_tenant(session.organization_id)
        membership = await uow.memberships.get_for_user(session.user_id)
        if membership is None or not membership.is_active:
            raise AuthenticationError

        access_token, access_expires = self._deps.codec.issue(
            subject=user.id,
            organization_id=session.organization_id,
            session_id=session.replaced_by_id,
            permissions=frozenset(p.value for p in membership.permissions),
            mfa_satisfied=user.mfa_enabled,
            ttl_seconds=self._deps.token_policy.access_ttl_seconds,
            now=now,
        )
        return TokenPair(
            access_token=access_token,
            access_token_expires_at=access_expires,
            refresh_token="",
            refresh_token_expires_at=session.expires_at,
            session_id=session.replaced_by_id,
        )

    async def _handle_reuse(
        self, uow: UnitOfWork, session: Session, context: RequestContext, now: datetime
    ) -> None:
        """A consumed token was replayed: revoke the whole family and record it."""
        revoked = await uow.sessions.revoke_family(
            session.family_id, now=now, reason=Session.REUSE_REVOCATION_REASON
        )
        await uow.bind_tenant(session.organization_id)
        user = await uow.users.get(session.user_id)
        await AuditRecorder(uow.audit).record(
            principal=None,
            organization_id=session.organization_id,
            actor_type=ActorType.USER,
            actor_user_id=session.user_id,
            actor_label=user.email.value if user else "",
            action=AuditAction.TOKEN_REUSE_DETECTED.value,
            resource_type="session",
            resource_id=session.id,
            outcome=AuditOutcome.DENIED,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={
                "family_id": str(session.family_id),
                "sessions_revoked": revoked,
                "rotated_at": session.rotated_at.isoformat() if session.rotated_at else None,
            },
        )
        await uow.commit()


class RevokeSession:
    """Sign out — the current session, or every session the user holds."""

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(self, *, principal: Principal, all_sessions: bool = False) -> int:
        now = self._deps.clock.now()
        async with self._uow as uow:
            if principal.user_id is None:  # pragma: no cover - guarded by the router
                raise InvalidStateError("Only a user session can be revoked.")

            if all_sessions:
                count = await uow.sessions.revoke_all_for_user(
                    principal.user_id, now=now, reason="user_logout_all"
                )
            elif principal.session_id is not None:
                session = await uow.sessions.get_by_id(principal.session_id)
                count = 0
                if session is not None:
                    count = await uow.sessions.revoke_family(
                        session.family_id, now=now, reason="user_logout"
                    )
            else:
                count = 0

            await uow.bind_tenant(principal.organization_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.LOGOUT.value,
                resource_type="user",
                resource_id=principal.user_id,
                metadata={"sessions_revoked": count, "all": all_sessions},
            )
            await uow.commit()
            return count


class ChangePassword:
    """Change a password, then invalidate every other session.

    Not revoking other sessions would make a password change useless as an incident
    response — the whole point is to evict whoever else is signed in.
    """

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(
        self, *, principal: Principal, current_password: str, new_password: str
    ) -> int:
        now = self._deps.clock.now()
        if principal.user_id is None:  # pragma: no cover - guarded by the router
            raise InvalidStateError("Only a signed-in user can change a password.")

        async with self._uow as uow:
            user = await uow.users.get(principal.user_id)
            if user is None or user.password_hash is None:
                raise NotFoundError("User", principal.user_id)
            if not self._deps.hasher.verify(current_password, user.password_hash.value):
                raise AuthenticationError("The current password is incorrect.")

            self._deps.password_policy.validate(
                new_password, context=(user.email.local_part, user.full_name)
            )
            if self._deps.hasher.verify(new_password, user.password_hash.value):
                raise ValidationError(
                    "The new password must differ from the current one.", field="new_password"
                )

            user.set_password(PasswordHash(self._deps.hasher.hash(new_password)), now)
            await uow.users.update(user)

            revoked = await uow.sessions.revoke_all_for_user(
                user.id,
                now=now,
                reason="password_changed",
                except_session_id=principal.session_id,
            )
            await uow.bind_tenant(principal.organization_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.PASSWORD_CHANGED.value,
                resource_type="user",
                resource_id=user.id,
                metadata={"other_sessions_revoked": revoked},
            )
            await uow.commit()
            return revoked


class DescribeCurrentPrincipal:
    """Assemble the ``GET /auth/me`` payload."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal) -> CurrentPrincipal:
        if principal.user_id is None:
            raise InvalidStateError("This endpoint is only available to user principals.")

        async with self._uow as uow:
            user = await uow.users.get(principal.user_id)
            organization = await uow.organizations.get(principal.organization_id)
            if user is None or organization is None:  # pragma: no cover - defensive
                raise NotFoundError("User", principal.user_id)

            await uow.bind_tenant(principal.organization_id)
            membership = await uow.memberships.get_for_user(principal.user_id)
            roles = list(membership.roles) if membership else []

            return CurrentPrincipal(
                user_id=user.id,
                email=user.email.value,
                full_name=user.full_name,
                mfa_enabled=user.mfa_enabled,
                is_platform_admin=user.is_platform_admin,
                organization=_org_summary(organization),
                roles=[_role_summary(r) for r in roles],
                permissions=sorted(p.value for p in principal.permissions),
                session_id=principal.session_id,
            )


class ResolveUserPrincipal:
    """Turn an access token into a :class:`Principal`.

    Permissions come from the database, not from the token's ``perms`` claim, so a role
    change applies on the next request instead of at token expiry (ADR-0006 §1.4).
    """

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(self, *, access_token: str, context: RequestContext) -> Principal:
        claims = self._deps.codec.decode(access_token, audience=USER_AUDIENCE)
        now = self._deps.clock.now()
        user_id = UUID(str(claims["sub"]))
        organization_id = UUID(str(claims["org"]))
        session_id = UUID(str(claims["sid"])) if claims.get("sid") else None

        async with self._uow as uow:
            user = await uow.users.get(user_id)
            if user is None or not user.is_active:
                raise AuthenticationError
            if user.is_locked(now):
                raise AuthenticationError

            if session_id is not None:
                session = await uow.sessions.get_by_id(session_id)
                if session is None or session.revoked_at is not None:
                    raise TokenError("This session has been revoked.")

            organization = await uow.organizations.get(organization_id)
            if organization is None or not organization.is_active:
                raise AuthenticationError

            await uow.bind_tenant(organization_id)
            membership = await uow.memberships.get_for_user(user_id)
            if membership is None or not membership.is_active:
                raise AuthenticationError

            return Principal.for_membership(
                membership,
                session_id=session_id,
                label=user.email.value,
                mfa_satisfied=bool(claims.get("mfa")),
                is_platform_admin=user.is_platform_admin,
                context=context,
            )


class ResolveApiKeyPrincipal:
    """Turn an ``ak_<prefix>.<secret>`` credential into a :class:`Principal`."""

    def __init__(self, uow: UnitOfWork, deps: AuthDependencies) -> None:
        self._uow = uow
        self._deps = deps

    async def execute(self, *, presented_key: str, context: RequestContext) -> Principal:
        from ..domain.value_objects import ApiKeyPrefix

        now = self._deps.clock.now()
        prefix_str, _, secret = _split_api_key(presented_key)
        try:
            prefix = ApiKeyPrefix(prefix_str)
        except Exception:
            self._deps.hasher.dummy_verify()
            raise AuthenticationError from None

        async with self._uow as uow:
            api_key = await uow.api_key_lookup.get_by_prefix(prefix)
            if api_key is None:
                self._deps.hasher.dummy_verify()
                raise AuthenticationError
            if not api_key.is_active(now):
                raise AuthenticationError
            if not self._deps.hasher.verify(secret, api_key.secret_hash):
                raise AuthenticationError

            organization = await uow.organizations.get(api_key.organization_id)
            if organization is None or not organization.is_active:
                raise AuthenticationError

            await uow.api_key_lookup.touch(api_key.id, now)
            await uow.commit()

            return Principal(
                kind=ActorType.API_KEY,
                organization_id=api_key.organization_id,
                permissions=api_key.permissions,
                api_key_id=api_key.id,
                label=f"api-key:{api_key.name}",
                mfa_satisfied=True,
                context=context,
            )


def _split_api_key(presented: str) -> tuple[str, str, str]:
    """Split ``ak_<prefix>.<secret>`` into its parts without raising on garbage."""
    raw = (presented or "").strip()
    body = raw[3:] if raw.startswith("ak_") else raw
    prefix, sep, secret = body.partition(".")
    return prefix, sep, secret


__all__ = [
    "AGENT_AUDIENCE",
    "MFA_CHALLENGE_AUDIENCE",
    "USER_AUDIENCE",
    "AuthDependencies",
    "AuthenticateUser",
    "ChangePassword",
    "CompleteMfaChallenge",
    "DescribeCurrentPrincipal",
    "Permission",
    "RefreshSession",
    "RegisterOrganization",
    "ResolveApiKeyPrincipal",
    "ResolveUserPrincipal",
    "RevokeSession",
    "SessionIssuer",
    "build_system_roles",
]
