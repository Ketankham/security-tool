"""Async engine/session factory.

Three ways to get a session, for three different shapes of caller:

- ``get_session`` — FastAPI dependency (``Depends(get_session)``). No
  implicit transaction; each route commits explicitly when it's done.
- ``session_scope`` — a *single* atomic unit of work: opens one transaction,
  commits on clean exit, rolls back on exception. Right for a short script
  or a one-shot task.
- ``open_session`` — a plain session with *no* implicit transaction, for
  callers (like the worker's multi-phase scan runner) that need several
  independent commits across one long-lived task. Using ``session_scope``
  there would be wrong: its enclosing ``session.begin()`` only expects to
  commit once, and an explicit ``session.commit()`` partway through leaves
  it holding a stale, already-closed transaction handle.
"""

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
    """A single atomic unit of work: one transaction, committed once on
    clean exit. See module docstring — do not call ``session.commit()``
    yourself inside this block; use ``open_session`` if you need to."""
    factory = _get_default_factory()
    async with factory() as session, session.begin():
        yield session


@asynccontextmanager
async def open_session() -> AsyncIterator[AsyncSession]:
    """A plain session with no implicit transaction — the caller commits
    (possibly several times) explicitly. See module docstring."""
    factory = _get_default_factory()
    async with factory() as session:
        yield session
