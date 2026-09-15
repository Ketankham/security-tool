"""API tests run against a real Postgres (see packages/db/tests/conftest.py
for the same pattern) and a real ASGI app via httpx's ASGITransport — no
mocked ORM, no mocked routing. Ownership verification's actual DNS/HTTP
calls are monkeypatched at the service-function level in the tests that
need them; everything else in the stack is real.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sentinel_db import Base
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

os.environ.setdefault("KMS_MASTER_KEY", "pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68=")

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
)


def pytest_collection_modifyitems(config, items):
    # Only tests that actually pull in the live-Postgres fixtures need the
    # `integration` marker (and its skip-if-unreachable behaviour) — plain
    # unit tests like test_ownership.py's mocked-DNS/HTTP cases stay fast
    # and run under `make test-unit` too.
    for item in items:
        if {"client", "db_engine"} & set(item.fixturenames):
            item.add_marker(pytest.mark.integration)


@pytest.fixture
async def db_engine():
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover
        await engine.dispose()
        pytest.skip(f"Postgres not reachable at {DATABASE_URL}: {exc}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def client(db_engine, monkeypatch):
    # Point the app's own session factory at our test engine/schema instead
    # of whatever DATABASE_URL the process-level settings would otherwise
    # build a *second*, untracked engine from.
    import sentinel_db.session as db_session_module

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(db_session_module, "_get_default_factory", lambda: factory)

    from sentinel_api_app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def no_dispatch(monkeypatch):
    """Scan creation calls out to Celery; tests don't need a live broker."""
    monkeypatch.setattr("sentinel_api_app.routers.scans.dispatch_scan", lambda scan_id: False)
