"""Scan cancellation: the Redis flag, the watch, long steps that stop when it
is set, and a whole scan closing as CANCELLED."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from redis.asyncio import Redis
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState
from sentinel_db.models import Organization, Scan, ScanEvent, ScanPhase, Target
from sentinel_recon import ReconResult
from sentinel_worker_app import cancel as cancel_mod
from sentinel_worker_app.cancel import (
    CancelWatch,
    ScanCancelled,
    cancel_key,
    run_until_cancelled,
)
from sentinel_worker_app.scan_runner import mark_scan_cancelled, run_scan
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

# --- The watch -----------------------------------------------------------------


async def test_the_key_matches_what_the_api_writes():
    scan_id = uuid.uuid4()
    assert cancel_key(scan_id) == f"sentinel:scan-cancel:{scan_id}"


async def test_requested_is_none_until_the_flag_is_set(redis_client):
    scan_id = uuid.uuid4()
    watch = CancelWatch(redis_client, scan_id)
    assert await watch.requested() is None
    await watch.raise_if_cancelled()  # nothing happens


async def test_the_flag_names_who_cancelled(redis_client):
    scan_id = uuid.uuid4()
    await redis_client.set(cancel_key(scan_id), "dana", ex=60)
    watch = CancelWatch(redis_client, scan_id)
    assert await watch.requested() == "dana"
    with pytest.raises(ScanCancelled) as excinfo:
        await watch.raise_if_cancelled()
    assert excinfo.value.by == "dana"


async def test_a_blank_flag_value_still_cancels_as_unknown(redis_client):
    scan_id = uuid.uuid4()
    await redis_client.set(cancel_key(scan_id), "  ", ex=60)
    assert await CancelWatch(redis_client, scan_id).requested() == "unknown"


async def test_the_flag_is_read_at_most_once_a_second(redis_client, monkeypatch):
    scan_id = uuid.uuid4()
    clock = [100.0]
    monkeypatch.setattr(cancel_mod.time, "monotonic", lambda: clock[0])
    watch = CancelWatch(redis_client, scan_id)
    assert await watch.requested() is None
    await redis_client.set(cancel_key(scan_id), "dana", ex=60)
    clock[0] += 0.4
    assert await watch.requested() is None  # cached: not looked at again yet
    clock[0] += 0.7
    assert await watch.requested() == "dana"


async def test_a_cancel_never_un_happens(redis_client):
    scan_id = uuid.uuid4()
    await redis_client.set(cancel_key(scan_id), "dana", ex=60)
    watch = CancelWatch(redis_client, scan_id)
    assert await watch.requested() == "dana"
    await redis_client.delete(cancel_key(scan_id))
    assert await watch.requested() == "dana"


async def test_clear_deletes_the_flag(redis_client):
    scan_id = uuid.uuid4()
    await redis_client.set(cancel_key(scan_id), "dana", ex=60)
    await CancelWatch(redis_client, scan_id).clear()
    assert await redis_client.get(cancel_key(scan_id)) is None


async def test_an_unreachable_redis_means_not_cancelled_not_a_crash():
    dead = Redis.from_url("redis://127.0.0.1:1/0")
    watch = CancelWatch(dead, uuid.uuid4())
    assert await watch.requested() is None
    await watch.raise_if_cancelled()
    await watch.clear()
    await dead.aclose()


# --- run_until_cancelled --------------------------------------------------------


class _Watch:
    def __init__(self, by: str | None = None) -> None:
        self.by = by

    async def requested(self) -> str | None:
        return self.by


async def test_a_step_that_finishes_returns_its_result():
    async def step() -> int:
        await asyncio.sleep(0.05)
        return 7

    assert await run_until_cancelled(step(), _Watch()) == 7


async def test_a_failing_step_raises_its_own_error():
    async def step() -> int:
        raise ValueError("nope")

    with pytest.raises(ValueError, match="nope"):
        await run_until_cancelled(step(), _Watch())


async def test_a_long_step_is_stopped_when_the_scan_is_cancelled():
    finished_cleanup = asyncio.Event()

    async def step() -> None:
        try:
            await asyncio.sleep(60)
        finally:
            finished_cleanup.set()  # engines and browsers are closed in finally blocks

    watch = _Watch()
    task = asyncio.ensure_future(run_until_cancelled(step(), watch))
    await asyncio.sleep(0.3)
    assert not task.done()
    watch.by = "dana"
    with pytest.raises(ScanCancelled) as excinfo:
        await asyncio.wait_for(task, timeout=5)
    assert excinfo.value.by == "dana"
    assert finished_cleanup.is_set()


async def test_cancelling_the_caller_cancels_the_step_too():
    inner_cancelled = asyncio.Event()

    async def step() -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            inner_cancelled.set()
            raise

    task = asyncio.ensure_future(run_until_cancelled(step(), _Watch()))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert inner_cancelled.is_set()


# --- Closing a scan as cancelled ----------------------------------------------


async def _scan_in(session, state, *, running_phase=None, requested_by=None):
    org = Organization(name="C", slug=f"c-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(
        organization_id=org.id,
        root_domain="c.test",
        display_name="C",
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id, state=state, requested_by=requested_by)
    session.add(scan)
    await session.flush()
    if running_phase is not None:
        session.add(ScanPhase(scan_id=scan.id, name=running_phase, status=PhaseStatus.RUNNING))
        session.add(
            ScanPhase(
                scan_id=scan.id, name=ScanPhaseName.SCOPE_VERIFYING, status=PhaseStatus.COMPLETED
            )
        )
    await session.commit()
    return scan


async def _events(db_engine, scan_id):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        return list(
            (
                await session.execute(
                    select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.seq)
                )
            ).scalars()
        )


async def test_mark_scan_cancelled_closes_the_scan_and_its_running_phase(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, ScanState.CRAWLING, running_phase=ScanPhaseName.CRAWLING)

    assert await mark_scan_cancelled(str(scan.id), "dana")

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.CANCELLED
        assert row.fail_reason == "Cancelled by dana."
        assert row.finished_at is not None
        phases = {p.name: p for p in row.phases}
        crawling = phases[ScanPhaseName.CRAWLING]
        assert crawling.status == PhaseStatus.FAILED
        assert crawling.error == "Cancelled by dana"
        assert crawling.finished_at is not None
        # a phase that had already finished is left alone
        assert phases[ScanPhaseName.SCOPE_VERIFYING].status == PhaseStatus.COMPLETED

    log_lines = [e.message for e in await _events(db_engine, scan.id)]
    assert "Scan cancelled by dana." in log_lines

    # Already terminal: left alone, nothing more is logged.
    assert not await mark_scan_cancelled(str(scan.id), "erin")
    async with factory() as session:
        assert (await session.get(Scan, scan.id)).fail_reason == "Cancelled by dana."


async def test_mark_scan_cancelled_ignores_a_missing_scan(db_engine):
    assert not await mark_scan_cancelled(str(uuid.uuid4()), "dana")


@pytest.mark.parametrize("state", [ScanState.COMPLETE, ScanState.FAILED])
async def test_mark_scan_cancelled_does_not_rewrite_a_finished_scan(db_engine, state):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, state)
    assert not await mark_scan_cancelled(str(scan.id), "dana")
    async with factory() as session:
        assert (await session.get(Scan, scan.id)).state == state


# --- A whole scan --------------------------------------------------------------


def _empty_recon() -> ReconResult:
    return ReconResult(
        root_domain="c.test",
        assets=[],
        tool_availability={},
        wildcard_dns_suspected=False,
        notes=[],
    )


async def test_a_scan_cancelled_while_queued_is_not_run(db_engine, redis_client):
    """The API closed it; the worker, picking the task up later, must not
    start it (and so must not overwrite CANCELLED)."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, ScanState.CANCELLED)
    await redis_client.set(cancel_key(scan.id), "dana", ex=60)

    recon = AsyncMock(return_value=_empty_recon())
    with patch("sentinel_worker_app.scan_runner.run_recon", new=recon):
        await run_scan(str(scan.id))

    recon.assert_not_called()
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.CANCELLED
        assert row.phases == []
    texts = [e.message for e in await _events(db_engine, scan.id)]
    assert any("Not started" in t and "cancelled" in t for t in texts)
    assert await redis_client.get(cancel_key(scan.id)) is None  # flag cleaned up


async def test_a_flag_set_before_the_worker_starts_ends_the_scan_as_cancelled(
    db_engine, redis_client
):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, ScanState.QUEUED, requested_by="alice")
    await redis_client.set(cancel_key(scan.id), "dana", ex=60)

    recon = AsyncMock(return_value=_empty_recon())
    with patch("sentinel_worker_app.scan_runner.run_recon", new=recon):
        await run_scan(str(scan.id))

    recon.assert_not_called()
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.CANCELLED
        assert row.fail_reason == "Cancelled by dana."
    assert "Scan cancelled by dana." in [e.message for e in await _events(db_engine, scan.id)]
    assert await redis_client.get(cancel_key(scan.id)) is None


async def test_cancelling_during_recon_stops_it_and_closes_the_phase(db_engine, redis_client):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, ScanState.QUEUED)

    recon_cleaned_up = asyncio.Event()

    async def slow_recon(*_args, **_kwargs):
        try:
            await asyncio.sleep(120)  # e.g. subfinder running
        finally:
            recon_cleaned_up.set()  # run_tool kills the process group on this path

    async def press_cancel():
        # wait until recon is really running, then cancel
        for _ in range(100):
            async with factory() as session:
                row = await session.get(Scan, scan.id)
                if row.state == ScanState.RECON:
                    break
            await asyncio.sleep(0.1)
        await redis_client.set(cancel_key(scan.id), "dana", ex=60)

    with patch("sentinel_worker_app.scan_runner.run_recon", new=slow_recon):
        presser = asyncio.ensure_future(press_cancel())
        await asyncio.wait_for(run_scan(str(scan.id)), timeout=60)
        await presser

    assert recon_cleaned_up.is_set()
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.CANCELLED
        assert row.fail_reason == "Cancelled by dana."
        assert row.finished_at is not None
        phases = {p.name: p for p in row.phases}
        assert phases[ScanPhaseName.SCOPE_VERIFYING].status == PhaseStatus.COMPLETED
        assert phases[ScanPhaseName.RECON].status == PhaseStatus.FAILED
        assert phases[ScanPhaseName.RECON].error == "Cancelled by dana"
        assert ScanPhaseName.CRAWLING not in phases  # nothing after the cancel was started
    texts = [e.message for e in await _events(db_engine, scan.id)]
    assert "Scan cancelled by dana." in texts
    assert await redis_client.get(cancel_key(scan.id)) is None
