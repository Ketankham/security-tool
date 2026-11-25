"""The worker's own authorisation gate for active tools: it trusts the
record, not the scan's options, and fails closed."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sentinel_db.models import Organization, Scan, ScanAuthorisation, Target
from sentinel_worker_app.active_tools import authorised_tools
from sentinel_worker_app.scan_runner import _run_active_tools
from sqlalchemy.ext.asyncio import async_sessionmaker

OPTIONS_ALL = {"dir_bruteforce": True, "port_scan": True, "all_ports": True, "speed": "gentle"}


class RecordingLog:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str, str]] = []

    def add(self, stage: str, message: str, *, level: str = "info", **_data) -> None:
        self.lines.append((stage, level, message))

    def add_secrets(self, _values) -> None:
        return None

    @property
    def messages(self) -> list[str]:
        return [m for _s, _l, m in self.lines]


async def _scan(session, options: dict) -> tuple[Scan, Target]:
    org = Organization(name="A", slug=f"a-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(organization_id=org.id, root_domain="a.test", display_name="A")
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id, options=options, requested_by="alice")
    session.add(scan)
    await session.flush()
    return scan, target


def _record(scan: Scan, target: Target, **kwargs) -> ScanAuthorisation:
    values = {
        "scan_id": scan.id,
        "target_id": target.id,
        "username": "alice",
        "accepted_at": datetime(2026, 11, 25, 9, 30, tzinfo=UTC),
        "statement_version": "1",
        "statement_text": "I confirm ...",
        "client_name": "Acme Ltd",
        "target_name": "a.test",
        "tools": ["dir_bruteforce", "port_scan", "all_ports"],
        "all_ports_confirmed": True,
        "target_environment": "production",
        "options_snapshot": {},
    }
    values.update(kwargs)
    return ScanAuthorisation(**values)


async def test_a_passive_scan_needs_no_authorisation_and_logs_nothing(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, _ = await _scan(session, {"speed": "normal", "dir_bruteforce": False})
        assert await authorised_tools(session, scan, log) == set()
        assert scan.is_degraded is False
    assert log.lines == []


async def test_requested_tools_without_a_record_are_refused_fail_closed(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, _ = await _scan(session, {"dir_bruteforce": True, "port_scan": True})
        assert await authorised_tools(session, scan, log) == set()
        expected = (
            "Directory brute force, Port scanning requested but no authorisation record with a "
            "signed-in user exists for this scan; skipped (fail closed)."
        )
        assert log.lines == [("scan", "warn", expected)]
        assert scan.is_degraded is True
        assert scan.degraded_reasons == [expected]


async def test_a_record_naming_nobody_is_not_an_authorisation(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    for blank in ("", "   "):
        log = RecordingLog()
        async with factory() as session:
            scan, target = await _scan(session, {"dir_bruteforce": True})
            session.add(_record(scan, target, username=blank))
            await session.flush()
            assert await authorised_tools(session, scan, log) == set()
            assert "fail closed" in log.messages[0]
            assert scan.is_degraded is True
            await session.rollback()


async def test_a_valid_record_authorises_what_it_covers_and_says_who(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, target = await _scan(session, OPTIONS_ALL)
        session.add(_record(scan, target))
        await session.flush()
        assert await authorised_tools(session, scan, log) == {
            "dir_bruteforce",
            "port_scan",
            "all_ports",
        }
        assert scan.is_degraded is False
    assert log.lines == [
        (
            "scan",
            "info",
            "Active tools authorised by alice at 2026-11-25T09:30:00+00:00 for client "
            "'Acme Ltd': Directory brute force, Port scanning, All 65,535 ports.",
        )
    ]


async def test_only_the_intersection_of_requested_and_recorded_tools_runs(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        # options were edited after the confirmation: port_scan was never confirmed
        scan, target = await _scan(session, {"dir_bruteforce": True, "port_scan": True})
        session.add(_record(scan, target, tools=["dir_bruteforce"], all_ports_confirmed=False))
        await session.flush()
        assert await authorised_tools(session, scan, log) == {"dir_bruteforce"}
        assert scan.is_degraded is True
        assert any(
            "Port scanning requested but not covered by the authorisation record" in m
            for m in log.messages
        )
        assert any(
            "authorised by alice" in m and m.endswith("Directory brute force.")
            for m in log.messages
        )


async def test_a_record_covering_tools_nobody_asked_for_does_not_add_them(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, target = await _scan(session, {"dir_bruteforce": True})
        session.add(_record(scan, target))  # covers all three
        await session.flush()
        assert await authorised_tools(session, scan, log) == {"dir_bruteforce"}


async def test_all_ports_without_its_confirmation_is_dropped(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, target = await _scan(session, {"port_scan": True, "all_ports": True})
        session.add(_record(scan, target, all_ports_confirmed=False))
        await session.flush()
        assert await authorised_tools(session, scan, log) == {"port_scan"}
        assert scan.is_degraded is True
        assert any("separate confirmation" in m for m in log.messages)


async def test_a_record_for_another_scan_is_not_used(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, target = await _scan(session, {"dir_bruteforce": True})
        other = Scan(target_id=target.id, options={"dir_bruteforce": True})
        session.add(other)
        await session.flush()
        session.add(_record(other, target))
        await session.flush()
        assert await authorised_tools(session, scan, log) == set()


# --- What scan_runner does with the answer -------------------------------------


class _NoCancel:
    async def raise_if_cancelled(self) -> None:
        return None


async def test_runner_says_not_implemented_for_authorised_tools_in_this_version(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, target = await _scan(session, {"dir_bruteforce": True, "port_scan": True})
        session.add(_record(scan, target))
        await session.flush()
        await _run_active_tools(session, scan, log, _NoCancel())
        messages = log.messages
        assert (
            "Directory brute force was requested but is not implemented in this version; skipped."
            in messages
        )
        assert (
            "Port scanning was requested but is not implemented in this version; skipped."
            in messages
        )
        assert scan.is_degraded is True
        assert len(scan.degraded_reasons) == 2


async def test_runner_does_not_claim_not_implemented_when_authorisation_failed_first(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, _ = await _scan(session, {"dir_bruteforce": True})  # no record
        await _run_active_tools(session, scan, log, _NoCancel())
        assert any("fail closed" in m for m in log.messages)
        assert not any("not implemented" in m for m in log.messages)


async def test_runner_does_nothing_for_a_passive_scan(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = RecordingLog()
    async with factory() as session:
        scan, _ = await _scan(session, {"speed": "normal"})
        await _run_active_tools(session, scan, log, _NoCancel())
        assert log.lines == []
        assert scan.is_degraded is False
