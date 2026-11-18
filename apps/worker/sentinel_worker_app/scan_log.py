"""The scan activity log writer (see sentinel_db.models.scan_event).

``ScanLog.add`` is synchronous and cheap (it only appends to a buffer), so
it can be called from anywhere, including the crawler's per-page callback.
A background task commits the buffer every couple of seconds on its own
database session, which is what lets the dashboard show the log *while the
scan runs*, independent of the scan runner's own multi-step transactions.

Rules:
- the log must never break a scan: every failure here is swallowed (and
  logged to the worker's own log);
- nothing secret goes in: messages and data go through sentinel_core.redact,
  plus any secret values the scan registered (a persona's session cookies);
- bounded: at most MAX_EVENTS lines per scan, then one "log full" line.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import structlog
from sentinel_core.redact import redact_text
from sentinel_db import open_session
from sentinel_db.models import ScanEvent
from sqlalchemy import func, select

log = structlog.get_logger(__name__)

MAX_EVENTS = 5000
# Errors are still recorded just past the cap, so a failure is never hidden.
_ERROR_HEADROOM = 50
_MESSAGE_LIMIT = 900
_DATA_VALUE_LIMIT = 300
_FLUSH_INTERVAL_S = 2.0


class NullScanLog:
    """Stands in when a caller (a unit test, a one-off helper) has no log."""

    def add(self, stage: str, message: str, **kwargs: Any) -> None:  # noqa: ARG002
        return None

    def add_secrets(self, values: Iterable[str]) -> None:  # noqa: ARG002
        return None


NULL_LOG = NullScanLog()


def _clean_data(data: dict[str, Any], secrets: set[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, bool | int | float) or value is None:
            out[key] = value
        else:
            out[key] = redact_text(str(value), secrets)[:_DATA_VALUE_LIMIT]
    return out


class ScanLog:
    def __init__(self, scan_id: uuid.UUID, *, start_seq: int = 0) -> None:
        self.scan_id = scan_id
        self._seq = start_seq
        self._buffer: list[ScanEvent] = []
        self._secrets: set[str] = set()
        self._dropped = 0
        self._capped = False
        self._task: asyncio.Task[None] | None = None
        self._flush_lock = asyncio.Lock()

    @classmethod
    async def resume(cls, scan_id: uuid.UUID) -> ScanLog:
        """A log that continues after the scan's existing events (used when a
        scan is closed as failed by something other than the scan runner)."""
        start = 0
        with contextlib.suppress(Exception):
            async with open_session() as session:
                start = (
                    await session.execute(
                        select(func.coalesce(func.max(ScanEvent.seq), 0)).where(
                            ScanEvent.scan_id == scan_id
                        )
                    )
                ).scalar_one()
        return cls(scan_id, start_seq=int(start))

    def add_secrets(self, values: Iterable[str]) -> None:
        self._secrets.update(v for v in values if v and len(v) >= 6)

    def add(
        self,
        stage: str,
        message: str,
        *,
        level: str = "info",
        persona: str | None = None,
        **data: Any,
    ) -> None:
        if level == "error":
            # Errors are still recorded just past the cap, so a failure is never hidden.
            if self._seq >= MAX_EVENTS + _ERROR_HEADROOM:
                self._dropped += 1
                return
        elif self._seq >= MAX_EVENTS:
            if not self._capped:
                self._capped = True
                self._append(
                    "scan",
                    f"Activity log is full ({MAX_EVENTS} lines); further detail is not recorded. "
                    "Errors are still logged.",
                    level="warn",
                    persona=None,
                    data={},
                )
            self._dropped += 1
            return
        self._append(stage, message, level=level, persona=persona, data=data)

    def _append(
        self, stage: str, message: str, *, level: str, persona: str | None, data: dict[str, Any]
    ) -> None:
        self._seq += 1
        self._buffer.append(
            ScanEvent(
                scan_id=self.scan_id,
                seq=self._seq,
                at=datetime.now(UTC),
                stage=stage[:40],
                level=level,
                persona=persona[:200] if persona else None,
                message=redact_text(message, self._secrets)[:_MESSAGE_LIMIT],
                data=_clean_data(data, self._secrets),
            )
        )

    async def flush(self) -> None:
        async with self._flush_lock:
            batch, self._buffer = self._buffer, []
            if not batch:
                return
            try:
                async with open_session() as session:
                    session.add_all(batch)
                    await session.commit()
            except Exception:  # noqa: BLE001 — the log must never break a scan
                log.warning("scan_log.flush_failed", scan_id=str(self.scan_id), exc_info=True)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._flush_loop())

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(_FLUSH_INTERVAL_S)
            await self.flush()

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        await self.flush()
