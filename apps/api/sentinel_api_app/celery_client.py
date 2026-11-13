"""Thin task-dispatch client. The API never imports the worker's Python
package (that would couple two independently-deployable services); it only
knows the Celery task *name* and sends to the shared broker, exactly as a
Celery app would if it defined no tasks of its own.

Dispatch failures (broker down) never fail the API request — the Scan row
is the source of truth (state=QUEUED), and a scheduled or manually-triggered
re-dispatch can pick it up later. See docs/01-architecture.md §3.1 (Celery
as "a dumb executor" over the persisted state machine).
"""

from __future__ import annotations

from functools import lru_cache

import structlog
from celery import Celery
from celery.result import AsyncResult

from .config import get_settings

log = structlog.get_logger(__name__)


@lru_cache
def _celery_app() -> Celery:
    settings = get_settings()
    return Celery("sentinel_api_client", broker=settings.redis_url, backend=settings.redis_url)


def dispatch_scan(scan_id: str) -> bool:
    """Returns True if the task was handed to the broker, False if dispatch
    failed (broker unreachable) — callers should not treat False as fatal."""
    try:
        _celery_app().send_task("scan.run", args=[scan_id])
        return True
    except Exception:  # noqa: BLE001 — broker connectivity issues are broad and expected here
        log.warning("celery_client.dispatch_failed", scan_id=scan_id, exc_info=True)
        return False


def dispatch_test_login(persona_id: str) -> str | None:
    """Queues the worker's persona.test_login on the "logins" queue (a
    small dedicated worker answers it even during a long scan). Returns the
    task id to poll, or None if the broker is unreachable."""
    try:
        result = _celery_app().send_task("persona.test_login", args=[persona_id], queue="logins")
        return str(result.id)
    except Exception:  # noqa: BLE001 — see dispatch_scan
        log.warning(
            "celery_client.test_login_dispatch_failed", persona_id=persona_id, exc_info=True
        )
        return None


def read_test_login(test_id: str) -> dict | None:
    """The finished test's result dict, or None while it is still queued or
    running (or if the id is unknown/expired — indistinguishable in Celery,
    so the dashboard gives up after a few minutes)."""
    result = AsyncResult(test_id, app=_celery_app())
    if not result.ready():
        return None
    value = result.result
    if isinstance(value, dict):
        return value
    # The task itself never raises (tasks.test_login_task), so this is a
    # worker-level failure such as a hard time limit.
    return {"success": False, "error": f"The login test failed: {value!r}"[:500]}
