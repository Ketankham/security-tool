"""Celery task definitions. Kept to a thin sync-to-async bridge — all real
logic lives in scan_runner.py (and test_login.py), which are plain async code
with zero Celery dependency and are unit-testable on their own.

Failure policy (v1): a scan that raises is marked FAILED with the reason and
is NOT retried automatically. An automatic retry re-ran the whole scan from
the top, against a scan row already part-way through its state machine, so
it failed again on an invalid transition and left the scan stuck mid-phase.
The dashboard's Retry button starts a fresh scan instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sentinel_db import dispose_default_engine

from .celery_app import celery_app
from .config import get_settings
from .scan_runner import mark_scan_failed, run_scan
from .test_login import run_test_login

log = structlog.get_logger(__name__)

_SETTINGS = get_settings()


T = TypeVar("T")


def _run(awaitable: Awaitable[T]) -> T:
    """asyncio.run, then drop the DB pool opened inside that loop (see
    sentinel_db.dispose_default_engine)."""

    async def _wrapped() -> T:
        try:
            return await awaitable
        finally:
            await dispose_default_engine()

    return asyncio.run(_wrapped())


def _short(exc: BaseException) -> str:
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return f"{type(exc).__name__}: {text}"[:600] if text else type(exc).__name__


@celery_app.task(
    name="scan.run",
    bind=True,
    soft_time_limit=_SETTINGS.scan_time_limit_s,
    time_limit=_SETTINGS.scan_time_limit_s + 120,
)
def run_scan_task(self, scan_id: str) -> None:
    try:
        _run(run_scan(scan_id))
    except SoftTimeLimitExceeded:
        hours = _SETTINGS.scan_time_limit_s / 3600
        log.error("tasks.run_scan_timed_out", scan_id=scan_id)
        _run(
            mark_scan_failed(
                scan_id, f"it ran longer than the {hours:g}-hour limit (SCAN_TIME_LIMIT_S)."
            )
        )
    except Exception as exc:
        log.error("tasks.run_scan_failed", scan_id=scan_id, exc_info=True)
        _run(mark_scan_failed(scan_id, f"unexpected error ({_short(exc)})."))


@celery_app.task(name="persona.test_login", soft_time_limit=150, time_limit=180)
def test_login_task(persona_id: str) -> dict:
    """Replays one persona's saved login and returns the outcome (with a
    screenshot) for the dashboard's Test login button. Never raises: every
    failure comes back as {"success": False, "error": ...}."""
    try:
        return _run(run_test_login(persona_id))
    except SoftTimeLimitExceeded:
        return {"persona_id": persona_id, "success": False, "error": "The login test timed out."}
    except Exception as exc:
        log.error("tasks.test_login_failed", persona_id=persona_id, exc_info=True)
        return {
            "persona_id": persona_id,
            "success": False,
            "error": f"The login test crashed: {_short(exc)}",
        }
