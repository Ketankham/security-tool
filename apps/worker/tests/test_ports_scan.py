"""Port scanning inside a whole scan (run_scan): the authorisation gate (no
record means not one connection), RECON stats and tool-run numbering, the flow
(ports, then directory, then crawl), crawl start pages from web services found
on unusual ports, the report, a missing naabu, cancel, and a step that crashes."""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from unittest.mock import AsyncMock, patch

import pytest
import sentinel_worker_test_fixture_dir_support as sup
import sentinel_worker_test_fixture_local_site as ls
import sentinel_worker_test_fixture_port_support as ps
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.models import (
    PortService,
    Report,
    Scan,
    ScanEvent,
    ScanPhase,
    ToolRunRecord,
)
from sentinel_recon import ToolRun
from sentinel_worker_app.cancel import cancel_key
from sentinel_worker_app.config import Settings, get_settings
from sentinel_worker_app.ports_adapter import PortStats, run_ports
from sentinel_worker_app.scan_runner import _in_scope_service_seeds, run_scan
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

needs_naabu = pytest.mark.skipif(shutil.which("naabu") is None, reason="naabu is not installed")

OPTIONS = {"port_scan": True, "speed": "fast"}


def _recon_with_run(site, *, host="127.0.0.1"):
    recon = sup.recon_for((host, site.port, "127.0.0.1"))
    run = ToolRun(tool="dns (built-in)", status="ok", command="A-record lookup", exit_code=0)
    return type(recon)(
        root_domain=recon.root_domain,
        assets=recon.assets,
        tool_availability={"subfinder": True, "httpx": True, "tlsx": True},
        wildcard_dns_suspected=False,
        tool_runs=[run],
    )


async def _scan(db_engine, options=None, **kwargs):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    kwargs.setdefault("tools", ["port_scan"])
    async with factory() as session:
        scan, target = await sup.scan_with_authorisation(session, options or OPTIONS, **kwargs)
    return factory, scan, target


async def _events(factory, scan_id):
    async with factory() as session:
        return list(
            (
                await session.execute(
                    select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.seq)
                )
            ).scalars()
        )


def _messages(events, stage=None):
    return [e.message for e in events if stage is None or e.stage == stage]


async def _run(scan, recon):
    with patch("sentinel_worker_app.scan_runner.run_recon", new=AsyncMock(return_value=recon)):
        await run_scan(str(scan.id))


def _with_tools(tools):
    """A run_ports stand-in that runs the real step with fake naabu/nmap."""

    async def step(*args, **kwargs):
        return await run_ports(*args, tools=tools, **kwargs)

    return step


async def _report_body(session, scan_id):
    report = (await session.execute(select(Report).where(Report.scan_id == scan_id))).scalar_one()
    return json.loads(
        await LocalTranscriptStore(get_settings().report_local_path).get(report.storage_pointer)
    )


# --- The whole thing, with the real naabu --------------------------------------------------


@needs_naabu
async def test_a_scan_with_port_scanning_finds_stores_and_reports_the_open_ports(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine)
    before = ps.naabu_pids()
    with (
        ps.listening(ps.TOP_1000_CANDIDATES) as listener,
        ps.listening(ps.high_port_candidates()) as high,
    ):
        await _run(scan, _recon_with_run(site))

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert recon.status == PhaseStatus.COMPLETED
        stats = recon.stats_json["ports"]
        assert stats["ips_planned"] == 1 and stats["ips_scanned"] == 1
        assert stats["open_ports"] >= 1 and stats["all_ports_ips"] == 0
        assert stats["nmap"] == "skipped" and stats["not_scanned"] == 0
        assert stats["suspicious_ips"] == 0

        ports = {
            p.port: p
            for p in (
                await session.execute(select(PortService).where(PortService.scan_id == scan.id))
            ).scalars()
        }
        assert listener.port in ports and high.port not in ports  # top-1000 only
        assert ports[listener.port].confidence == "port_guess"
        assert ports[listener.port].ip == "127.0.0.1" and ports[listener.port].hosts == [
            "127.0.0.1"
        ]

        runs = list(
            (
                await session.execute(
                    select(ToolRunRecord)
                    .where(ToolRunRecord.scan_id == scan.id)
                    .order_by(ToolRunRecord.seq)
                )
            ).scalars()
        )
        assert [(r.seq, r.tool, r.status) for r in runs] == [
            (1, "dns (built-in)", "ok"),
            (2, "naabu", "ok"),
        ]
        assert runs[1].version.startswith("v2.")

        body = await _report_body(session, scan.id)
        assert body["authorisation"]["tools"] == ["port_scan"]
        assert listener.port in {p["port"] for p in body["ports"]}
        assert body["summary"]["open_ports"] == len(body["ports"]) >= 1
        assert all("scripts" not in p for p in body["ports"])
        assert "port scanning and service detection (active tool)" in body["checks_run"]

    events = await _events(factory, scan.id)
    ports_log = _messages(events, "ports")
    assert any(
        m.startswith("Port scan of 1 IP(s): top 1,000 TCP ports, connect scan, 200 packets/s")
        and m.endswith("Authorised by alice.")
        for m in ports_log
    )
    assert any(f"{listener.port}" in m and "open:" in m for m in ports_log)
    assert await ps.no_naabu_left(before)


# --- The gate -----------------------------------------------------------------------------


async def test_without_an_authorisation_record_not_one_connection_is_made(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine, authorised=False)
    step = AsyncMock()
    with (
        ps.listening(ps.TOP_1000_CANDIDATES) as listener,
        patch("sentinel_worker_app.scan_runner.run_ports", new=step),
    ):
        await _run(scan, _recon_with_run(site))
        assert listener.connections == 0

    step.assert_not_called()
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert row.is_degraded and any("fail closed" in r for r in row.degraded_reasons)
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert "ports" not in recon.stats_json
        assert (
            await session.execute(select(PortService).where(PortService.scan_id == scan.id))
        ).first() is None
        runs = (
            await session.execute(select(ToolRunRecord).where(ToolRunRecord.scan_id == scan.id))
        ).scalars()
        assert [r.tool for r in runs] == ["dns (built-in)"]
        body = await _report_body(session, scan.id)
        assert body["ports"] == [] and "open_ports" not in body["summary"]
        assert "port scanning and service detection (active tool)" in body["checks_skipped"]
    events = await _events(factory, scan.id)
    assert any("fail closed" in m for m in _messages(events, "scan"))
    assert _messages(events, "ports") == []


async def test_a_record_that_does_not_cover_port_scanning_runs_nothing(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine, tools=["dir_bruteforce"])
    step = AsyncMock()
    with (
        ps.listening(ps.TOP_1000_CANDIDATES) as listener,
        patch("sentinel_worker_app.scan_runner.run_ports", new=step),
    ):
        await _run(scan, _recon_with_run(site))
        assert listener.connections == 0
    step.assert_not_called()
    async with factory() as session:
        row = await session.get(Scan, scan.id)
        assert row.state == ScanState.COMPLETE
        assert any("not covered by the authorisation record" in r for r in row.degraded_reasons)


async def test_a_record_without_the_all_ports_confirmation_never_scans_all_ports(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    options = {"port_scan": True, "all_ports": True, "recon_profile": "full", "speed": "fast"}
    factory, scan, _ = await _scan(
        db_engine, options, tools=["port_scan", "all_ports"], all_ports_confirmed=False
    )
    from_naabu = ps.FakeNaabu({"127.0.0.1": []})
    with patch(
        "sentinel_worker_app.scan_runner.run_ports",
        new=_with_tools(ps.fake_tools(from_naabu, nmap_installed=False)),
    ):
        await _run(scan, _recon_with_run(site))
    assert [c["all_ports"] for c in from_naabu.calls] == [False]
    async with factory() as session:
        row = await session.get(Scan, scan.id)
        assert any("separate confirmation" in r for r in row.degraded_reasons)


async def test_a_passive_scan_never_touches_the_step(db_engine, redis_client, make_site):
    site = make_site(ls.planted_site())
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan, _ = await sup.scan_with_authorisation(session, {"speed": "fast"}, authorised=False)
    step = AsyncMock()
    with patch("sentinel_worker_app.scan_runner.run_ports", new=step):
        await _run(scan, _recon_with_run(site))
    step.assert_not_called()


# --- naabu missing --------------------------------------------------------------------------


async def test_a_missing_naabu_lets_the_scan_finish_degraded(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine)
    real_which = shutil.which
    monkeypatch.setattr(
        "sentinel_recon.tooling.shutil.which",
        lambda name, *a, **k: None if name in ("naabu", "nmap") else real_which(name, *a, **k),
    )
    with ps.listening(ps.TOP_1000_CANDIDATES) as listener:
        await _run(scan, _recon_with_run(site))
        assert listener.connections == 0

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert any("naabu is not installed" in r for r in row.degraded_reasons)
        runs = list(
            (
                await session.execute(
                    select(ToolRunRecord)
                    .where(ToolRunRecord.scan_id == scan.id)
                    .order_by(ToolRunRecord.seq)
                )
            ).scalars()
        )
        assert [(r.tool, r.status) for r in runs] == [
            ("dns (built-in)", "ok"),
            ("naabu", "not_installed"),
        ]
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert recon.stats_json["ports"]["ips_scanned"] == 0
        body = await _report_body(session, scan.id)
        assert "port scanning and service detection (active tool)" in body["checks_skipped"]
    warn = [e for e in await _events(factory, scan.id) if e.stage == "ports"]
    assert warn and all(e.level == "warn" for e in warn)


# --- The flow: ports, directory, crawl ---------------------------------------------------------


async def test_ports_run_before_the_directory_step_and_the_numbering_continues(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    options = {"port_scan": True, "dir_bruteforce": True, "speed": "fast"}
    factory, scan, _ = await _scan(db_engine, options, tools=["port_scan", "dir_bruteforce"])
    order: list[str] = []
    naabu = ps.FakeNaabu({"127.0.0.1": [8081]})
    real_step = _with_tools(ps.fake_tools(naabu, nmap_installed=False))

    async def ports_step(*args, **kwargs):
        order.append("ports")
        return await real_step(*args, **kwargs)

    async def dir_step(*args, **kwargs):
        order.append("dir")
        order.append(f"dir seq {args[10]}")
        from sentinel_worker_app.dir_bruteforce_adapter import DirStats

        return DirStats(next_seq=args[10])

    with (
        patch("sentinel_worker_app.scan_runner.run_ports", new=ports_step),
        patch("sentinel_worker_app.scan_runner.run_dir_bruteforce", new=dir_step),
    ):
        await _run(scan, _recon_with_run(site))

    # dns run = 1, naabu = 2, so the directory step starts at 3
    assert order == ["ports", "dir", "dir seq 3"]
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert "ports" in recon.stats_json and "dir_bruteforce" in recon.stats_json
        assert recon.stats_json["ports"]["open_ports"] == 1


async def test_a_web_service_found_on_an_unusual_port_becomes_a_crawl_start_page(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    other = make_site({"/": ls.Reply(200, "<html><body>second app</body></html>")})
    options = {"port_scan": True, "speed": "fast", "recon_profile": "full"}
    factory, scan, _ = await _scan(db_engine, options)
    naabu = ps.FakeNaabu({"127.0.0.1": [other.port, 22]})
    nmap = ps.FakeNmap(
        {
            "127.0.0.1": [
                ps.service(other.port, "http", product="python"),
                ps.service(22, "ssh"),
            ]
        }
    )
    with patch(
        "sentinel_worker_app.scan_runner.run_ports", new=_with_tools(ps.fake_tools(naabu, nmap))
    ):
        await _run(scan, _recon_with_run(site))

    events = await _events(factory, scan.id)
    crawl = _messages(events, "crawl")
    assert any(
        "web service(s) that port scanning found on non-standard ports" in m
        and f"http://127.0.0.1:{other.port}/" in m
        for m in crawl
    )
    assert "/" in other.paths  # the crawl really started from it
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert recon.stats_json["ports"]["nmap"] == "ran"
        body = await _report_body(session, scan.id)
        assert {p["port"]: p["confidence"] for p in body["ports"]} == {
            other.port: "detected",
            22: "detected",
        }


async def test_crawl_start_pages_from_services_are_checked_again_against_scope_and_the_guard():
    stats = PortStats(
        web_seeds=[
            "http://app.acme.test:8080/",
            "https://other.example:8443/",  # not the target's host
            "http://127.0.0.1:9000/",  # a private address
            "http://app.acme.test:8080/",  # a duplicate
            "http://app.acme.test:8081/admin/",  # excluded by a path rule
        ]
    )
    guard = sup.guard_for({"app.acme.test"}, [sup.rule("path_prefix", "/admin")])
    private_off = Settings(allow_private_addresses=False)
    assert await _in_scope_service_seeds(stats, guard, private_off) == [
        "http://app.acme.test:8080/"
    ]
    assert await _in_scope_service_seeds(None, guard, private_off) == []


# --- Cancel -----------------------------------------------------------------------------------


@needs_naabu
async def test_cancelling_during_the_port_scan_ends_the_scan_cancelled_and_leaves_no_process(
    db_engine, redis_client, make_site
):
    site = make_site(ls.planted_site())
    options = {"port_scan": True, "speed": "gentle"}  # 50 packets/s: about 40 s if left alone
    factory, scan, _ = await _scan(db_engine, options)
    before = ps.naabu_pids()

    async def press_cancel():
        for _ in range(300):
            if ps.naabu_pids() - before:
                break
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        await redis_client.set(cancel_key(scan.id), "dana", ex=120)

    presser = asyncio.ensure_future(press_cancel())
    await asyncio.wait_for(_run(scan, _recon_with_run(site)), timeout=90)
    await presser

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.CANCELLED and row.fail_reason == "Cancelled by dana."
        phases = {p.name: p for p in row.phases}
        assert phases[ScanPhaseName.RECON].status == PhaseStatus.FAILED
        assert ScanPhaseName.CRAWLING not in phases
        runs = {
            r.tool: r
            for r in (
                await session.execute(select(ToolRunRecord).where(ToolRunRecord.scan_id == scan.id))
            ).scalars()
        }
        assert runs["naabu"].status == "cancelled"
        assert runs["naabu"].skip_reason == "Cancelled by dana"
    assert "Scan cancelled by dana." in _messages(await _events(factory, scan.id), "scan")
    assert await ps.no_naabu_left(before)


# --- A step that goes wrong -----------------------------------------------------------------------


async def test_a_crashing_step_costs_the_step_not_the_scan(db_engine, redis_client, make_site):
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine)
    boom = AsyncMock(side_effect=RuntimeError("something broke"))
    with patch("sentinel_worker_app.scan_runner.run_ports", new=boom):
        await _run(scan, _recon_with_run(site))
    async with factory() as session:
        row = await session.get(Scan, scan.id)
        assert row.state == ScanState.COMPLETE
        assert any(
            "Port scanning crashed and was skipped: RuntimeError: something broke" in r
            for r in row.degraded_reasons
        )
    assert any(e.level == "error" and e.stage == "ports" for e in await _events(factory, scan.id))


async def test_a_database_error_in_the_step_is_recovered_from(db_engine, redis_client, make_site):
    """A failed flush leaves the session needing a rollback; the scan must go on."""
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine)

    async def bad_step(session, *_args, **_kwargs):
        session.add(
            PortService(
                scan_id=uuid.uuid4(),  # no such scan: the flush fails
                ip="127.0.0.1",
                port=80,
                protocol="tcp",
                state="open",
                confidence="port_guess",
                found_by="naabu",
            )
        )
        await session.flush()

    with patch("sentinel_worker_app.scan_runner.run_ports", new=bad_step):
        await _run(scan, _recon_with_run(site))
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert any("Port scanning crashed" in r for r in row.degraded_reasons)
        phases = {p.name: p for p in row.phases}
        assert phases[ScanPhaseName.RECON].status == PhaseStatus.COMPLETED
        assert phases[ScanPhaseName.REPORTING].status == PhaseStatus.COMPLETED
        assert (
            await session.execute(select(ScanPhase).where(ScanPhase.scan_id == scan.id))
        ).first() is not None
