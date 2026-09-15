"""Async engine/session factory. Use ``get_session`` as a FastAPI dependency
or ``session_scope`` as a plain async context manager in Celery tasks."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .settings import DbSettings


def make_engine(database_url: str | None = None) -> AsyncEngine:
    url = database_url or DbSettings().database_url
    return create_async_engine(url, pool_pre_ping=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_default_factory() -> async_sessionmaker[AsyncSession]:
    global _engine, _session_factory
    if _session_factory is None:
        _engine = make_engine()
        _session_factory = make_session_factory(_engine)
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: ``session: AsyncSession = Depends(get_session)``."""
    factory = _get_default_factory()
    async with factory() as session:
        yield session


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Plain async context manager for Celery tasks / scripts."""
    factory = _get_default_factory()
    async with factory() as session, session.begin():
        yield session
