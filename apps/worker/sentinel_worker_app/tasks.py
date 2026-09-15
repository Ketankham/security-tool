"""Celery task definitions. Kept to a thin sync-to-async bridge — all real
logic lives in scan_runner.py, which is plain async code with zero Celery
dependency and is unit-testable on its own.
"""

from __future__ import annotations

import asyncio

import structlog

from .celery_app import celery_app
from .scan_runner import run_scan

log = structlog.get_logger(__name__)


@celery_app.task(name="scan.run", bind=True, max_retries=3, default_retry_delay=30)
def run_scan_task(self, scan_id: str) -> None:
    try:
        asyncio.run(run_scan(scan_id))
    except Exception as exc:
        log.error("tasks.run_scan_failed", scan_id=scan_id, exc_info=True)
        raise self.retry(exc=exc) from exc
