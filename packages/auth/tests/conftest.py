"""Serves the real test fixture apps on a real bound port so Playwright
(and, for sentinel_crawler, the crawler itself) can drive them like any
other website — no mocking the browser or the network.

Fixture app modules are loaded by file path (importlib.util), not by
package import: this repo has already hit the same-named-top-level-package
collision bug twice (apps/api vs apps/worker's `app`, and `tests/__init__`
across packages) when two unrelated directories share a plain name like
`fixtures` in one shared environment. Loading by path sidesteps that
entirely — the module is registered under a name unique to this file, never
found by another package's import.
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
from pathlib import Path
from types import ModuleType

import pytest
import uvicorn
from playwright.async_api import async_playwright
from sentinel_auth.browser import chromium_launch_kwargs


def _load_module(unique_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(unique_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_login_app_module = _load_module(
    "sentinel_auth_test_fixture_login_app", Path(__file__).parent / "fixtures" / "login_app.py"
)
login_app = _login_app_module.app


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
async def login_server():
    port = _free_port()
    server, task = await _serve(login_app, port)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def browser():
    async with async_playwright() as p:
        b = await p.chromium.launch(**chromium_launch_kwargs())
        yield b
        await b.close()
