"""Worker tests run scan_runner.run_scan against a real Postgres (same
pattern as apps/api/tests, packages/db/tests) with sentinel_recon's network
calls (DNS/HTTP) mocked — the recon package's own tests already cover that
logic; these tests cover the *orchestration* (state machine + DB writes).
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
        if "db_engine" in item.fixturenames:
            item.add_marker(pytest.mark.integration)


@pytest.fixture
async def db_engine(monkeypatch):
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover
        await engine.dispose()
        pytest.skip(f"Postgres not reachable at {DATABASE_URL}: {exc}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Point sentinel_db's module-level session factory at this test engine —
    # scan_runner imports `open_session`, which resolves lazily against
    # whatever the module's default factory is at call time.
    import sentinel_db.session as db_session_module
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db_session_module, "_get_default_factory", lambda: factory)

    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
