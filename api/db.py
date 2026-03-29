"""
Async SQLAlchemy engine and session factory for the Olympus FOIA backend.

Uses SQLite (aiosqlite) in development and PostgreSQL in production.
Switch via the DATABASE_URL environment variable.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.config import get_settings


def _make_engine():
    settings = get_settings()
    url = settings.database_url
    # Transparently upgrade bare postgresql:// to the asyncpg driver so that
    # callers can use the standard DATABASE_URL convention without knowing
    # about SQLAlchemy async dialect prefixes.
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://") :]
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_async_engine(url, connect_args=connect_args, echo=False)


engine = _make_engine()

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session and ensure it is closed afterwards.

    Yields:
        AsyncSession: An open database session.
    """
    async with AsyncSessionLocal() as session:
        yield session
