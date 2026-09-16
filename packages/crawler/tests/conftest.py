"""Serves the crawler's mini test app on a real bound port — same
path-based module loading as packages/auth/tests/conftest.py (see that
file's docstring for why: no relative-import package collisions)."""

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


def _chromium_launch_kwargs() -> dict:
    # Duplicated from sentinel_auth.browser rather than imported: this
    # package doesn't otherwise depend on sentinel-auth, and a shared
    # 6-line launch-args helper isn't worth an inter-package test
    # dependency. See that module's docstring for why the override exists.
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


_mini_app_module = _load_module(
    "sentinel_crawler_test_fixture_mini_app", Path(__file__).parent / "fixtures" / "mini_app.py"
)
mini_app = _mini_app_module.app


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
async def mini_app_server():
    port = _free_port()
    server, task = await _serve(mini_app, port)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def browser():
    async with async_playwright() as p:
        b = await p.chromium.launch(**_chromium_launch_kwargs())
        yield b
        await b.close()
