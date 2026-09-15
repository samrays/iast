"""Async engine and session factory."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ...config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Build the async engine."""
    url = settings.effective_database_url
    if "sqlite" in url:
        return create_async_engine(
            url,
            echo=settings.database_echo,
        )
    return create_async_engine(
        url,
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "server_settings": {
                "application_name": settings.service_name,
                # Fail a runaway query rather than holding a connection forever.
                "statement_timeout": "30000",
                "idle_in_transaction_session_timeout": "60000",
            }
        },
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )


async def dispose_engine(engine: AsyncEngine) -> None:
    await engine.dispose()
