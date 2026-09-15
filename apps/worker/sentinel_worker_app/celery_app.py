"""Celery application. Tasks are dumb executors over the persisted scan
state machine (docs/01-architecture.md §3.1) — this file only wires up the
broker/backend and task discovery; all the actual logic lives in
scan_runner.py so it's independently unit-testable without Celery at all.
"""

from __future__ import annotations

from celery import Celery

from .config import get_settings

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
)

# Import so the @celery_app.task-decorated functions register themselves.
from . import tasks  # noqa: E402,F401
