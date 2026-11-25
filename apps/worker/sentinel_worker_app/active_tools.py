"""Which active tools this scan is actually authorised to run.

The API refuses an active-tool request without a signed-in user and the
"I'm authorised" confirmation, and stores that confirmation with the scan
before it is dispatched. The worker does not take that on trust: it looks the
record up itself and, if it is missing or names nobody, runs nothing (fail
closed) and says so in the log and the scan's coverage notes. Whatever the
scan's options ask for, only the tools the record covers can run.
"""

from __future__ import annotations

from sentinel_core import scan_options
from sentinel_db.models import Scan, ScanAuthorisation
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .scan_log import NullScanLog, ScanLog


def _names(tools: list[str] | set[str]) -> str:
    ordered = [t for t in scan_options.ACTIVE_TOOL_KEYS if t in tools]
    return ", ".join(scan_options.ACTIVE_TOOL_LABELS[t] for t in ordered)


def _skip(scan: Scan, scan_log: ScanLog | NullScanLog, message: str) -> None:
    scan_log.add("scan", message, level="warn")
    scan.is_degraded = True
    scan.degraded_reasons = [*scan.degraded_reasons, message]


async def authorised_tools(
    session: AsyncSession, scan: Scan, scan_log: ScanLog | NullScanLog
) -> set[str]:
    """The subset of the scan's requested active tools that its authorisation
    record covers. Empty (with a warning in the log and a degraded reason)
    when tools were requested but nothing authorises them."""
    requested = scan_options.active_tools(scan.options)
    if not requested:
        return set()

    row = (
        await session.execute(select(ScanAuthorisation).where(ScanAuthorisation.scan_id == scan.id))
    ).scalar_one_or_none()
    if row is None or not (row.username or "").strip():
        _skip(
            scan,
            scan_log,
            f"{_names(requested)} requested but no authorisation record with a signed-in user "
            "exists for this scan; skipped (fail closed).",
        )
        return set()

    allowed = set(requested) & set(row.tools or [])
    if "all_ports" in allowed and not row.all_ports_confirmed:
        allowed.discard("all_ports")
        _skip(
            scan,
            scan_log,
            "All 65,535 ports was requested but its separate confirmation is not on the "
            "authorisation record; skipped (fail closed).",
        )
    not_covered = set(requested) - set(row.tools or [])
    if not_covered:
        _skip(
            scan,
            scan_log,
            f"{_names(not_covered)} requested but not covered by the authorisation record; "
            "skipped (fail closed).",
        )
    if allowed:
        scan_log.add(
            "scan",
            f"Active tools authorised by {row.username} at "
            f"{row.accepted_at.isoformat(timespec='seconds')} for client '{row.client_name}': "
            f"{_names(allowed)}.",
        )
    return allowed


async def authorising_user(session: AsyncSession, scan: Scan) -> str:
    """Who confirmed the authorisation for this scan ('unknown' if no record)."""
    row = (
        await session.execute(select(ScanAuthorisation).where(ScanAuthorisation.scan_id == scan.id))
    ).scalar_one_or_none()
    return (row.username or "").strip() if row is not None and row.username else "unknown"
