"""Composition root.

The single place where concrete adapters are chosen and wired to ports. Everything else in
the application depends on interfaces, which is what makes the layering in ADR-0002 real
rather than aspirational.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from .application.auth import AuthDependencies
from .config import Settings
from .infrastructure.clock import SystemClock
from .infrastructure.db.engine import create_engine, create_session_factory, dispose_engine
from .infrastructure.db.unit_of_work import SqlUnitOfWork
from .infrastructure.security import (
    Argon2PasswordHasher,
    FernetCipher,
    JwtAccessTokenCodec,
    OpaqueTokenGenerator,
    PyOtpTotpService,
)


@dataclass
class Container:
    """Holds the process-wide singletons and hands out per-request units of work."""

    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    auth: AuthDependencies

    def unit_of_work(self) -> SqlUnitOfWork:
        """A fresh unit of work. Never share one across requests — it owns a transaction."""
        return SqlUnitOfWork(self.session_factory)

    async def aclose(self) -> None:
        await dispose_engine(self.engine)


def build_container(settings: Settings) -> Container:
    engine = create_engine(settings)
    session_factory = create_session_factory(engine)

    hasher = Argon2PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost_kib=settings.argon2_memory_cost_kib,
        parallelism=settings.argon2_parallelism,
    )
    codec = JwtAccessTokenCodec(
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        issuer=settings.jwt_issuer,
        private_key=settings.jwt_private_key,
        public_key=settings.jwt_public_key,
    )
    # Falling back to the JWT secret keeps a fresh local clone working. Production refuses
    # to start without an explicit key — see Settings._validate_secrets.
    cipher = FernetCipher([settings.secret_encryption_key or settings.jwt_secret])

    auth = AuthDependencies(
        clock=SystemClock(),
        hasher=hasher,
        tokens=OpaqueTokenGenerator(),
        codec=codec,
        totp=PyOtpTotpService(
            digits=settings.mfa_policy.digits,
            period_seconds=settings.mfa_policy.period_seconds,
            valid_window=settings.mfa_valid_window,
        ),
        cipher=cipher,
        password_policy=settings.password_policy,
        lockout_policy=settings.lockout_policy,
        token_policy=settings.token_policy,
    )

    return Container(settings=settings, engine=engine, session_factory=session_factory, auth=auth)
