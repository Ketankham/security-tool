"""Celery application. Tasks are dumb executors over the persisted scan
state machine (docs/01-architecture.md §3.1) — this file only wires up the
broker/backend and task discovery; all the actual logic lives in
scan_runner.py so it's independently unit-testable without Celery at all.

Queues: scans go to the default "celery" queue; login tests go to "logins"
so a test answers in seconds even while a long scan is running (the
deployment runs a small second worker on that queue only).
"""

from __future__ import annotations

import asyncio

import structlog
from celery import Celery
from celery.signals import worker_ready

from .config import get_settings

log = structlog.get_logger(__name__)

settings = get_settings()

celery_app = Celery(
    "sentinel_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    # Login-test results (with a screenshot) only need to live long enough
    # for the dashboard to fetch them.
    result_expires=3600,
    task_routes={"persona.test_login": {"queue": "logins"}},
)


@worker_ready.connect
def _fail_interrupted_scans(**_: object) -> None:
    """See scan_runner.fail_interrupted_scans. Only the scan worker does
    this (the login-test worker sets SWEEP_INTERRUPTED_SCANS=false)."""
    if not get_settings().sweep_interrupted_scans:
        return
    from sentinel_db import dispose_default_engine

    from .scan_runner import fail_interrupted_scans

    async def _sweep() -> None:
        try:
            await fail_interrupted_scans()
        finally:
            await dispose_default_engine()

    try:
        asyncio.run(_sweep())
    except Exception:  # noqa: BLE001 — never stop the worker from starting
        log.error("celery_app.sweep_failed", exc_info=True)


# Import so the @celery_app.task-decorated functions register themselves.
from . import tasks  # noqa: E402,F401
