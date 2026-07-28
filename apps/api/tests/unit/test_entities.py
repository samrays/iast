"""Entity invariants and state machines."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis_api.domain.entities import (
    Agent,
    AgentStatus,
    ApiKey,
    Application,
    ApplicationEnvironment,
    Criticality,
    EnvironmentKind,
    Language,
    License,
    LicenseTier,
    Membership,
    MembershipStatus,
    MfaCredential,
    MfaKind,
    Organization,
    OrganizationStatus,
    ProtectionMode,
    Role,
    Session,
    User,
    UserStatus,
)
from aegis_api.domain.errors import (
    AccountDisabledError,
    AccountLockedError,
    InvalidStateError,
    LicenseLimitExceededError,
    PermissionDeniedError,
    PrivilegeEscalationError,
)
from aegis_api.domain.permissions import (
    SYSTEM_ROLE_PERMISSIONS,
    Permission,
    SystemRole,
)
from aegis_api.domain.policies import LockoutPolicy
from aegis_api.domain.value_objects import (
    ApiKeyPrefix,
    EmailAddress,
    PasswordHash,
    Slug,
    TokenHash,
    new_id,
)

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
HASH = PasswordHash("$argon2id$v=19$m=65536,t=3,p=4$abc$def")


def _digest(seed: str) -> TokenHash:
    import hashlib

    return TokenHash(hashlib.sha256(seed.encode()).hexdigest())


class TestOrganization:
    def test_requires_a_name(self) -> None:
        with pytest.raises(InvalidStateError):
            Organization(name="  ", slug=Slug("acme"))

    def test_suspend_and_reactivate(self) -> None:
        org = Organization(name="Acme", slug=Slug("acme"))
        org.suspend("non-payment")
        assert org.status is OrganizationStatus.SUSPENDED
        assert org.settings["suspension_reason"] == "non-payment"
        org.reactivate()
        assert org.is_active
        assert "suspension_reason" not in org.settings

    def test_deletion_is_two_phase(self) -> None:
        org = Organization(name="Acme", slug=Slug("acme"))
        org.schedule_deletion(NOW + timedelta(days=30))
        assert org.status is OrganizationStatus.PENDING_DELETION
        with pytest.raises(InvalidStateError):
            org.reactivate()
        org.cancel_deletion()
        assert org.is_active

    def test_cancel_deletion_requires_pending_state(self) -> None:
        with pytest.raises(InvalidStateError):
            Organization(name="Acme", slug=Slug("acme")).cancel_deletion()


class TestLicense:
    def test_tier_entitlements(self) -> None:
        trial = License.for_tier(new_id(), LicenseTier.TRIAL)
        assert trial.max_applications == 3
        assert not trial.ai_enabled

        enterprise = License.for_tier(new_id(), LicenseTier.ENTERPRISE)
        assert enterprise.max_applications == -1
        assert enterprise.protection_enabled

    def test_limits_are_enforced(self) -> None:
        license_ = License.for_tier(new_id(), LicenseTier.TRIAL)
        license_.check_applications(2)
        with pytest.raises(LicenseLimitExceededError):
            license_.check_applications(3)

    def test_unlimited_never_raises(self) -> None:
        license_ = License.for_tier(new_id(), LicenseTier.ENTERPRISE)
        license_.check_agents(1_000_000)
        license_.check_users(1_000_000)

    def test_validity_window(self) -> None:
        license_ = License.for_tier(new_id(), LicenseTier.TEAM, valid_until=NOW)
        assert not license_.is_valid(NOW + timedelta(seconds=1))
        assert license_.is_valid(NOW - timedelta(seconds=1))


class TestUser:
    def test_lockout_after_repeated_failures(self) -> None:
        policy = LockoutPolicy(max_failed_attempts=3, base_seconds=60)
        user = User(email=EmailAddress("a@example.com"), password_hash=HASH)
        for _ in range(3):
            user.record_failed_login(NOW, policy)
        assert user.is_locked(NOW)
        assert user.lock_retry_after(NOW) == 60
        with pytest.raises(AccountLockedError):
            user.assert_can_authenticate(NOW)

    def test_successful_login_clears_lock_state(self) -> None:
        policy = LockoutPolicy(max_failed_attempts=1, base_seconds=60)
        user = User(email=EmailAddress("a@example.com"), password_hash=HASH)
        user.record_failed_login(NOW, policy)
        user.record_successful_login(NOW + timedelta(minutes=5))
        assert user.failed_login_count == 0
        assert user.locked_until is None

    def test_disabled_account_cannot_authenticate(self) -> None:
        user = User(email=EmailAddress("a@example.com"), status=UserStatus.DISABLED)
        with pytest.raises(AccountDisabledError):
            user.assert_can_authenticate(NOW)

    def test_setting_a_password_activates_an_invited_user(self) -> None:
        user = User(email=EmailAddress("a@example.com"), status=UserStatus.INVITED)
        user.set_password(HASH, NOW)
        assert user.status is UserStatus.ACTIVE
        assert user.password_changed_at == NOW

    def test_platform_admin_cannot_be_disabled_here(self) -> None:
        user = User(email=EmailAddress("a@example.com"), is_platform_admin=True)
        with pytest.raises(InvalidStateError):
            user.disable()

    def test_lock_expires(self) -> None:
        policy = LockoutPolicy(max_failed_attempts=1, base_seconds=60)
        user = User(email=EmailAddress("a@example.com"))
        user.record_failed_login(NOW, policy)
        assert not user.is_locked(NOW + timedelta(seconds=61))
        assert user.lock_retry_after(NOW + timedelta(seconds=61)) == 0


class TestMfaCredential:
    def test_recovery_code_is_single_use(self) -> None:
        code = MfaCredential(user_id=new_id(), kind=MfaKind.RECOVERY_CODE, secret_encrypted="x")
        assert code.is_usable
        code.consume(NOW)
        assert not code.is_usable
        with pytest.raises(InvalidStateError):
            code.consume(NOW)

    def test_totp_is_unusable_until_confirmed(self) -> None:
        totp = MfaCredential(user_id=new_id(), kind=MfaKind.TOTP, secret_encrypted="x")
        assert not totp.is_usable
        totp.confirm(NOW)
        assert totp.is_usable

    def test_kind_specific_operations_are_guarded(self) -> None:
        totp = MfaCredential(user_id=new_id(), kind=MfaKind.TOTP, secret_encrypted="x")
        with pytest.raises(InvalidStateError):
            totp.consume(NOW)
        code = MfaCredential(user_id=new_id(), kind=MfaKind.RECOVERY_CODE, secret_encrypted="x")
        with pytest.raises(InvalidStateError):
            code.confirm(NOW)


class TestRoleAndMembership:
    def test_permissions_are_the_union_of_roles(self) -> None:
        org = new_id()
        reader = Role(
            organization_id=org, name="Reader", permissions=frozenset({Permission.APP_READ})
        )
        writer = Role(
            organization_id=org, name="Writer", permissions=frozenset({Permission.APP_WRITE})
        )
        membership = Membership(organization_id=org, user_id=new_id(), roles=(reader, writer))
        assert membership.permissions == {Permission.APP_READ, Permission.APP_WRITE}

    def test_suspended_membership_has_no_permissions(self) -> None:
        org = new_id()
        role = Role(organization_id=org, name="Owner", permissions=frozenset(Permission))
        membership = Membership(
            organization_id=org,
            user_id=new_id(),
            roles=(role,),
            status=MembershipStatus.SUSPENDED,
        )
        assert membership.permissions == frozenset()
        with pytest.raises(PermissionDeniedError):
            membership.require(Permission.APP_READ)

    def test_cannot_carry_another_tenants_role(self) -> None:
        foreign = Role(organization_id=new_id(), name="Reader")
        with pytest.raises(InvalidStateError):
            Membership(organization_id=new_id(), user_id=new_id(), roles=(foreign,))

    def test_cannot_grant_permissions_it_does_not_hold(self) -> None:
        org = new_id()
        role = Role(
            organization_id=org, name="Reader", permissions=frozenset({Permission.APP_READ})
        )
        membership = Membership(organization_id=org, user_id=new_id(), roles=(role,))
        membership.assert_can_grant(frozenset({Permission.APP_READ}))
        with pytest.raises(PrivilegeEscalationError):
            membership.assert_can_grant(frozenset({Permission.ROLE_WRITE}))

    def test_system_roles_are_immutable(self) -> None:
        role = Role.system(new_id(), SystemRole.OWNER, frozenset(Permission), "Owner")
        with pytest.raises(InvalidStateError):
            role.update(name="Renamed")

    def test_custom_role_cannot_take_owner_only_permissions(self) -> None:
        role = Role(organization_id=new_id(), name="Custom")
        with pytest.raises(InvalidStateError):
            role.update(permissions=frozenset({Permission.ORG_DELETE}))

    def test_membership_must_retain_a_role(self) -> None:
        membership = Membership(organization_id=new_id(), user_id=new_id())
        with pytest.raises(InvalidStateError):
            membership.assign_roles(())

    def test_owner_detection(self) -> None:
        org = new_id()
        owner_role = Role.system(
            org, SystemRole.OWNER, SYSTEM_ROLE_PERMISSIONS[SystemRole.OWNER], "Owner"
        )
        assert Membership(organization_id=org, user_id=new_id(), roles=(owner_role,)).is_owner

    def test_viewer_role_is_read_only(self) -> None:
        viewer = SYSTEM_ROLE_PERMISSIONS[SystemRole.VIEWER]
        assert all(p.value.endswith(":read") for p in viewer)


class TestSession:
    def _session(self) -> Session:
        return Session.start(
            user_id=new_id(),
            organization_id=new_id(),
            refresh_token_hash=_digest("one"),
            ttl_seconds=3600,
            now=NOW,
        )

    def test_start_creates_its_own_family(self) -> None:
        session = self._session()
        assert session.family_id == session.id
        assert session.is_active(NOW)

    def test_rotation_inherits_family_and_absolute_expiry(self) -> None:
        session = self._session()
        successor = session.rotate(
            refresh_token_hash=_digest("two"),
            now=NOW + timedelta(minutes=5),
            absolute_expiry=session.expires_at,
        )
        assert successor.family_id == session.family_id
        # Rotation must not extend the family's life, or a stolen token could be refreshed
        # forever.
        assert successor.expires_at == session.expires_at
        assert session.is_rotated
        assert not session.is_active(NOW + timedelta(minutes=5))
        assert session.replaced_by_id == successor.id

    def test_rotation_grace_window(self) -> None:
        session = self._session()
        session.rotate(
            refresh_token_hash=_digest("two"), now=NOW, absolute_expiry=session.expires_at
        )
        assert session.is_within_rotation_grace(NOW + timedelta(seconds=5), 10)
        assert not session.is_within_rotation_grace(NOW + timedelta(seconds=30), 10)

    def test_revoked_session_cannot_rotate(self) -> None:
        session = self._session()
        session.revoke(NOW, "test")
        with pytest.raises(InvalidStateError):
            session.rotate(
                refresh_token_hash=_digest("two"), now=NOW, absolute_expiry=session.expires_at
            )

    def test_revoke_is_idempotent(self) -> None:
        session = self._session()
        session.revoke(NOW, "first")
        session.revoke(NOW + timedelta(minutes=1), "second")
        assert session.revoked_reason == "first"

    def test_expiry(self) -> None:
        session = self._session()
        assert session.is_expired(NOW + timedelta(hours=2))
        assert not session.is_active(NOW + timedelta(hours=2))


class TestApiKey:
    def test_activity_window(self) -> None:
        key = ApiKey(
            organization_id=new_id(),
            name="ci",
            prefix=ApiKeyPrefix("abc123DEF456"),
            secret_hash="$argon2id$x",
            expires_at=NOW + timedelta(days=1),
        )
        assert key.is_active(NOW)
        assert not key.is_active(NOW + timedelta(days=2))
        key.revoke(NOW)
        assert not key.is_active(NOW)

    def test_requires_a_name(self) -> None:
        with pytest.raises(InvalidStateError):
            ApiKey(
                organization_id=new_id(),
                name=" ",
                prefix=ApiKeyPrefix("abc123DEF456"),
                secret_hash="$x",
            )

    def test_permission_check(self) -> None:
        key = ApiKey(
            organization_id=new_id(),
            name="ci",
            prefix=ApiKeyPrefix("abc123DEF456"),
            secret_hash="$x",
            permissions=frozenset({Permission.AGENT_WRITE}),
        )
        key.require(Permission.AGENT_WRITE)
        with pytest.raises(PermissionDeniedError):
            key.require(Permission.ORG_DELETE)


class TestInventory:
    def test_criticality_weights_are_ordered(self) -> None:
        weights = [
            c.weight
            for c in (Criticality.LOW, Criticality.MEDIUM, Criticality.HIGH, Criticality.CRITICAL)
        ]
        assert weights == sorted(weights)

    def test_application_requires_a_name(self) -> None:
        with pytest.raises(InvalidStateError):
            Application(organization_id=new_id(), name="", slug=Slug("x"), language=Language.JAVA)

    def test_exposure_weight_favours_internet_facing_production(self) -> None:
        org, app = new_id(), new_id()
        dev = ApplicationEnvironment(
            organization_id=org, application_id=app, kind=EnvironmentKind.DEVELOPMENT
        )
        prod = ApplicationEnvironment(
            organization_id=org,
            application_id=app,
            kind=EnvironmentKind.PRODUCTION,
            internet_facing=True,
        )
        assert prod.exposure_weight > dev.exposure_weight

    def test_production_cannot_block_before_the_soak(self) -> None:
        env = ApplicationEnvironment(
            organization_id=new_id(),
            application_id=new_id(),
            kind=EnvironmentKind.PRODUCTION,
            protection_mode=ProtectionMode.OFF,
        )
        env.set_protection_mode(ProtectionMode.MONITOR, NOW)
        with pytest.raises(InvalidStateError, match="monitor mode"):
            env.set_protection_mode(ProtectionMode.BLOCK, NOW + timedelta(days=1))
        env.set_protection_mode(ProtectionMode.BLOCK, NOW + timedelta(days=15))
        assert env.protection_mode is ProtectionMode.BLOCK

    def test_non_production_can_block_immediately(self) -> None:
        env = ApplicationEnvironment(
            organization_id=new_id(), application_id=new_id(), kind=EnvironmentKind.QA
        )
        env.set_protection_mode(ProtectionMode.BLOCK, NOW)
        assert env.protection_mode is ProtectionMode.BLOCK


class TestAgent:
    def _agent(self) -> Agent:
        return Agent(
            organization_id=new_id(),
            application_environment_id=new_id(),
            fingerprint="fp-1234567890",
            hostname="host-1",
            agent_version="0.4.0",
            runtime_version="21",
            language=Language.JAVA,
        )

    def test_heartbeat_marks_online(self) -> None:
        agent = self._agent()
        agent.record_heartbeat(now=NOW, cpu_overhead_pct=1.2, memory_mb=80, events_sent=5)
        assert agent.status is AgentStatus.ONLINE
        assert agent.events_sent == 5

    def test_high_overhead_marks_degraded(self) -> None:
        agent = self._agent()
        agent.record_heartbeat(now=NOW, cpu_overhead_pct=9.5)
        assert agent.status is AgentStatus.DEGRADED

    def test_disabled_hooks_mark_degraded(self) -> None:
        agent = self._agent()
        agent.record_heartbeat(now=NOW, cpu_overhead_pct=0.5, health={"hooks_disabled": 3})
        assert agent.status is AgentStatus.DEGRADED

    def test_missed_heartbeats_mark_offline(self) -> None:
        agent = self._agent()
        agent.record_heartbeat(now=NOW)
        agent.evaluate_liveness(NOW + timedelta(seconds=60))
        assert agent.status is AgentStatus.ONLINE
        agent.evaluate_liveness(NOW + timedelta(seconds=200))
        assert agent.status is AgentStatus.OFFLINE

    def test_disabled_agent_may_not_report(self) -> None:
        agent = self._agent()
        agent.disable()
        with pytest.raises(InvalidStateError):
            agent.record_heartbeat(now=NOW)
        # A disabled agent is also left alone by the liveness sweep.
        agent.evaluate_liveness(NOW + timedelta(days=1))
        assert agent.status is AgentStatus.DISABLED

    def test_requires_a_fingerprint(self) -> None:
        with pytest.raises(InvalidStateError):
            Agent(
                organization_id=new_id(),
                application_environment_id=new_id(),
                fingerprint="  ",
                hostname="h",
                agent_version="1",
                runtime_version="1",
                language=Language.GO,
            )
