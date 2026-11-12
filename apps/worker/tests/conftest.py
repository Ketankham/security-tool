"""Worker tests run scan_runner against a real Postgres (same pattern as
apps/api/tests, packages/db/tests), a real Redis (fakeredis is a poor fit
here since the rate limiter uses WATCH/MULTI across two separately-opened
Redis clients within one test), and a real login-gated fixture app driven
by a real headless browser — see fixtures/persona_app.py. Only
sentinel_recon's network calls (DNS/HTTP) are mocked; that package's own
tests already cover that logic in isolation, and it has no notion of a
docker-compose-style port mapping to a local fixture (see
tests/benchmark/README.md for the same gap).
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import socket
from pathlib import Path
from types import ModuleType

import pytest
import uvicorn
from playwright.async_api import async_playwright
from redis.asyncio import Redis
from sentinel_db import Base
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _chromium_launch_kwargs() -> dict:
    # Duplicated from sentinel_auth.browser rather than imported — see
    # packages/crawler/tests/conftest.py's identical helper for why.
    kwargs: dict = {"headless": True}
    chromium_path = os.environ.get("SENTINEL_CHROMIUM_PATH")
    if chromium_path:
        kwargs["executable_path"] = chromium_path
    return kwargs


def _load_module(unique_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(unique_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_persona_app_module = _load_module(
    "sentinel_worker_test_fixture_persona_app",
    Path(__file__).parent / "fixtures" / "persona_app.py",
)
persona_app = _persona_app_module.app

_multi_tenant_app_module = _load_module(
    "sentinel_worker_test_fixture_multi_tenant_app",
    Path(__file__).parent / "fixtures" / "multi_tenant_app.py",
)
multi_tenant_app = _multi_tenant_app_module.app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _serve(app, port: int):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, task


@pytest.fixture
async def persona_app_server():
    port = _free_port()
    server, task = await _serve(persona_app, port)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def multi_tenant_app_server():
    port = _free_port()
    server, task = await _serve(multi_tenant_app, port)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def browser():
    async with async_playwright() as p:
        b = await p.chromium.launch(**_chromium_launch_kwargs())
        yield b
        await b.close()


@pytest.fixture
async def redis_client():
    client: Redis = Redis.from_url(REDIS_URL)
    try:
        await client.ping()
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"Redis not reachable at {REDIS_URL}: {exc}")
    yield client
    await client.flushdb()
    await client.aclose()


_INTEGRATION_FIXTURES = {
    "db_engine",
    "redis_client",
    "browser",
    "persona_app_server",
    "multi_tenant_app_server",
}


def pytest_collection_modifyitems(config, items):
    for item in items:
        if _INTEGRATION_FIXTURES & set(item.fixturenames):
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
