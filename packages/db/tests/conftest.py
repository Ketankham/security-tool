"""Integration tests here talk to a real Postgres (docker-compose / `make up`,
or the natively-installed postgres+redis this sandbox uses when Docker Hub
isn't reachable). Skipped automatically if DATABASE_URL_SYNC isn't reachable.
"""

from __future__ import annotations

import os

import pytest
from sentinel_db import Base
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
)


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


@pytest.fixture
async def engine():
    eng = create_async_engine(DATABASE_URL)
    try:
        async with eng.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover
        await eng.dispose()
        pytest.skip(f"Postgres not reachable at {DATABASE_URL}: {exc}")
    yield eng
    await eng.dispose()


@pytest.fixture
async def session_factory(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
