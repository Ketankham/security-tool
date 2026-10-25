"""Serves the authz fixture app on a real bound port so the authorization
engine drives it through the real HttpEngine. Same load-by-path pattern as
sentinel_auth's conftest, to avoid the shared-top-level-name collisions a
monorepo hits when two packages both have a `fixtures` dir."""

from __future__ import annotations

import asyncio
import importlib.util
import socket
from pathlib import Path
from types import ModuleType

import pytest
import uvicorn


def _load_module(unique_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(unique_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_authz_app_module = _load_module(
    "sentinel_checks_test_fixture_authz_app",
    Path(__file__).parent / "fixtures" / "authz_app.py",
)
authz_app = _authz_app_module.app


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
async def authz_server():
    port = _free_port()
    server, task = await _serve(authz_app, port)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task
