"""Benchmark fixtures aren't part of the default test run (they need the
heavy docker-compose.yml in this directory up and running) — every test
here is marked `benchmark` and skips cleanly if its target isn't reachable,
the same convention as `integration` elsewhere in this repo."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        item.add_marker(pytest.mark.benchmark)
