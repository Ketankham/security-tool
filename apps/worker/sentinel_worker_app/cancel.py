"""Cooperative scan cancellation.

``POST /scans/{id}/cancel`` (the API) leaves a flag in Redis,
``sentinel:scan-cancel:{scan_id}``, whose value is who asked. The worker
checks it at every phase boundary, between hosts/IPs inside the active tools,
and (through ``cancel_check``) about once a second while an external tool is
running, so Stop takes effect within a second or so inside a tool and at the
next step otherwise.

Cancelling never leaves anything running: sentinel_recon.tooling.run_tool
kills the tool's whole process group, and ``run_until_cancelled`` cancels a
long phase's task, whose own ``finally`` blocks close engines and browsers.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable
from typing import TypeVar

import structlog
from redis.asyncio import Redis

log = structlog.get_logger(__name__)

CANCEL_KEY_PREFIX = "sentinel:scan-cancel:"
_CACHE_SECONDS = 1.0
_REDIS_TIMEOUT_S = 2.0

T = TypeVar("T")


def cancel_key(scan_id: object) -> str:
    return f"{CANCEL_KEY_PREFIX}{scan_id}"


class ScanCancelled(Exception):  # noqa: N818 — reads as the event, not an error class
    """The scan was cancelled; ``by`` is who asked ('unknown' when not signed in)."""

    def __init__(self, by: str) -> None:
        super().__init__(f"Scan cancelled by {by}")
        self.by = by


class CancelWatch:
    """Reads the cancel flag, at most once a second. A Redis outage means
    "not cancelled" (the scan carries on) rather than a crashed scan; the
    next successful read picks the flag up."""

    def __init__(self, redis: Redis, scan_id: object) -> None:
        self._redis = redis
        self._key = cancel_key(scan_id)
        self._checked_at = float("-inf")
        self._by: str | None = None
        self._warned = False

    async def requested(self) -> str | None:
        """Who asked for the scan to stop, or None."""
        if self._by is not None:
            return self._by  # a cancel never un-happens
        now = time.monotonic()
        if now - self._checked_at < _CACHE_SECONDS:
            return None
        self._checked_at = now
        try:
            value = await asyncio.wait_for(self._redis.get(self._key), timeout=_REDIS_TIMEOUT_S)
        except Exception:  # noqa: BLE001 — see class docstring
            if not self._warned:
                self._warned = True
                log.warning("cancel.redis_unavailable", key=self._key, exc_info=True)
            return None
        if value is None:
            return None
        text = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
        self._by = text.strip() or "unknown"
        return self._by

    async def raise_if_cancelled(self) -> None:
        by = await self.requested()
        if by is not None:
            raise ScanCancelled(by)

    async def clear(self) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._redis.delete(self._key), timeout=_REDIS_TIMEOUT_S)


async def run_until_cancelled(awaitable: Awaitable[T], watch: CancelWatch) -> T:
    """Run a long step, stopping it (by cancelling its task) soon after the
    scan is cancelled; raises ScanCancelled then. If the caller itself is
    cancelled the step is cancelled and awaited too."""
    task = asyncio.ensure_future(awaitable)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=_CACHE_SECONDS)
            if done:
                return task.result()
            by = await watch.requested()
            if by is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
                raise ScanCancelled(by)
    except BaseException:
        if not task.done():
            task.cancel()
            with contextlib.suppress(BaseException):
                await task
        raise
