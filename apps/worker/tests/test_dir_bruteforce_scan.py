"""Directory brute force inside a whole scan (run_scan): the authorisation
gate, RECON stats and tool-run numbering, crawl seeds, no duplicate passive
finding, the report, cancel, and a step that crashes."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from unittest.mock import AsyncMock, patch

import pytest
import sentinel_worker_test_fixture_dir_support as sup
import sentinel_worker_test_fixture_local_site as ls
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.enums import FindingConfidence
from sentinel_db.models import (
    DiscoveredPath,
    Finding,
    Report,
    Scan,
    ScanEvent,
    ScanPhase,
    ToolRunRecord,
)
from sentinel_recon import ToolRun, wordlists
from sentinel_worker_app import dir_bruteforce_adapter
from sentinel_worker_app.cancel import cancel_key
from sentinel_worker_app.config import get_settings
from sentinel_worker_app.scan_runner import run_scan
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

needs_ffuf = pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf is not installed")

OPTIONS = {"dir_bruteforce": True, "speed": "fast"}
WORDS = (
    ("config", ".env"),
    ("config", "config.json"),
    ("vcs", ".git/HEAD"),
    ("admin", "admin/"),
    ("admin", "secret-area/x"),
    ("backup", "backup.zip"),
    ("backup", "old.zip"),
)


def _recon_with_run(site):
    recon = sup.recon_for(("127.0.0.1", site.port, "127.0.0.1"))
    run = ToolRun(tool="dns (built-in)", status="ok", command="A-record lookup", exit_code=0)
    return type(recon)(
        root_domain=recon.root_domain,
        assets=recon.assets,
        tool_availability={"subfinder": True, "httpx": True, "tlsx": True},
        wildcard_dns_suspected=False,
        tool_runs=[run],
    )


def _patch_wordlist(monkeypatch, *pairs, bulk=0):
    monkeypatch.setattr(wordlists, "load", sup.wordlist_loader(*pairs, bulk=bulk))


async def _scan(db_engine, **kwargs):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan, target = await sup.scan_with_authorisation(session, OPTIONS, **kwargs)
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


# --- The whole thing ------------------------------------------------------------


@needs_ffuf
async def test_a_scan_with_directory_brute_force_finds_proves_and_reports(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    _patch_wordlist(monkeypatch, *WORDS)
    factory, scan, target = await _scan(db_engine)
    from sentinel_db.models import ScopeRule

    async with factory() as session:
        session.add(
            ScopeRule(
                target_id=target.id,
                kind="path_prefix",
                pattern="/secret-area",
                effect="exclude",
                label="no secrets",
            )
        )
        await session.commit()

    await _run(scan, _recon_with_run(site))

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert recon.status == PhaseStatus.COMPLETED
        stats = recon.stats_json["dir_bruteforce"]
        assert stats["hosts_planned"] == 1 and stats["hosts_run"] == 1
        assert stats["entries"] == 7 and stats["entries_removed_by_scope"] == 1
        assert stats["wordlist"] == "sentinel-core" and stats["wordlist_sha256"] == "ab" * 32
        assert stats["confirmed"] == 3 and stats["hits"] == 4  # .env .git/HEAD backup.zip admin/
        assert stats["stopped_hosts"] == 0 and stats["not_run_hosts"] == 0

        paths = {
            p.path: p
            for p in (
                await session.execute(
                    select(DiscoveredPath).where(DiscoveredPath.scan_id == scan.id)
                )
            ).scalars()
        }
        assert {p: r.verdict for p, r in paths.items()} == {
            "/.env": "confirmed",
            "/.git/HEAD": "confirmed",
            "/backup.zip": "confirmed",
            "/admin/": "found",
        }

        # One finding per file: the passive check did not report .env / .git again.
        findings = list(
            (
                await session.execute(
                    select(Finding)
                    .where(Finding.scan_id == scan.id)
                    .options(selectinload(Finding.verification))
                )
            ).scalars()
        )
        by_rule: dict[str, list[Finding]] = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f)
        for rule in ("exposed.env_file", "exposed.git_repository", "exposed.backup_file"):
            assert len(by_rule[rule]) == 1, rule
            assert by_rule[rule][0].confidence is FindingConfidence.CONFIRMED
            assert by_rule[rule][0].verification.reproduced_count == 2
        assert paths["/.env"].finding_id == by_rule["exposed.env_file"][0].id

        # Tool runs continue the numbering after recon's own run.
        runs = list(
            (
                await session.execute(
                    select(ToolRunRecord)
                    .where(ToolRunRecord.scan_id == scan.id)
                    .order_by(ToolRunRecord.seq)
                )
            ).scalars()
        )
        assert [(r.seq, r.tool) for r in runs] == [
            (1, "dns (built-in)"),
            (2, "ffuf"),
            (3, "head-pass (built-in)"),
        ]

        # The report carries the paths and who authorised them.
        report = (
            await session.execute(select(Report).where(Report.scan_id == scan.id))
        ).scalar_one()
        body = json.loads(
            await LocalTranscriptStore(get_settings().report_local_path).get(report.storage_pointer)
        )
        assert body["authorisation"]["username"] == "alice"
        assert body["authorisation"]["client_name"] == "Acme Ltd"
        assert body["authorisation"]["tools"] == ["dir_bruteforce"]
        assert {p["path"]: p["verdict"] for p in body["paths"]}["/.env"] == "confirmed"
        assert body["summary"]["paths_found"] == 4 and body["summary"]["paths_confirmed"] == 3
        assert "directory and file brute force (active tool)" in body["checks_run"]
        assert ls.ENV_SECRET not in json.dumps(body)

    events = await _events(factory, scan.id)
    dirlog = _messages(events, "dir_bruteforce")
    assert any(
        m.startswith(
            "Directory brute force on 1 host(s) with sentinel-core (7 entries, sha256 abababababab)"
        )
        and m.endswith("one host at a time. Authorised by alice.")
        for m in dirlog
    )
    assert any(m.startswith("Running: ffuf ") and "(pinned to 127.0.0.1)" in m for m in dirlog)
    assert any("127.0.0.1: 4 path(s) found, 3 confirmed" in m for m in dirlog)
    crawl = _messages(events, "crawl")
    assert any(
        "found by directory brute force" in m and f"{site.origin}/admin/" in m for m in crawl
    )
    assert any(
        "already confirmed by directory brute force" in m
        for m in _messages(events, "passive_checks")
    )
    # the activity log says nothing of the secret either
    stored = await sup.everything_stored(
        db_engine, get_settings().storage_local_path, get_settings().report_local_path
    )
    assert ls.ENV_SECRET not in stored and "sk-live-0123456789abcdef" not in stored
    # nothing excluded was ever requested
    assert not [p for p in site.paths if p.startswith("/secret-area")]


async def test_without_an_authorisation_record_the_step_is_skipped_fail_closed(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    _patch_wordlist(monkeypatch, *WORDS)
    factory, scan, _ = await _scan(db_engine, authorised=False)

    await _run(scan, _recon_with_run(site))

    assert site.requests == []  # not one request, baseline included
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert row.is_degraded and any("fail closed" in r for r in row.degraded_reasons)
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert "dir_bruteforce" not in recon.stats_json
        assert (
            await session.execute(select(DiscoveredPath).where(DiscoveredPath.scan_id == scan.id))
        ).first() is None
        runs = (
            await session.execute(select(ToolRunRecord).where(ToolRunRecord.scan_id == scan.id))
        ).scalars()
        assert [r.tool for r in runs] == ["dns (built-in)"]
        report = (
            await session.execute(select(Report).where(Report.scan_id == scan.id))
        ).scalar_one()
        body = json.loads(
            await LocalTranscriptStore(get_settings().report_local_path).get(report.storage_pointer)
        )
        assert body["authorisation"] is None
        assert "directory and file brute force (active tool)" in body["checks_skipped"]
    events = await _events(factory, scan.id)
    assert any("fail closed" in m for m in _messages(events, "scan"))
    assert _messages(events, "dir_bruteforce") == []


async def test_a_record_that_does_not_cover_the_tool_runs_nothing(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    _patch_wordlist(monkeypatch, *WORDS)
    factory, scan, _ = await _scan(db_engine, tools=["port_scan"])
    await _run(scan, _recon_with_run(site))
    assert site.requests == []
    async with factory() as session:
        row = await session.get(Scan, scan.id)
        assert row.state == ScanState.COMPLETE
        assert any("not covered by the authorisation record" in r for r in row.degraded_reasons)


async def test_a_passive_scan_does_not_touch_the_step(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    _patch_wordlist(monkeypatch, *WORDS)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan, _ = await sup.scan_with_authorisation(session, {"speed": "fast"}, authorised=False)
    step = AsyncMock()
    with patch("sentinel_worker_app.scan_runner.run_dir_bruteforce", new=step):
        await _run(scan, _recon_with_run(site))
    step.assert_not_called()
    assert site.requests == []


async def test_a_missing_ffuf_lets_the_scan_finish_degraded(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    _patch_wordlist(monkeypatch, *WORDS)
    monkeypatch.setattr(dir_bruteforce_adapter, "tool_available", lambda _name: False)
    factory, scan, _ = await _scan(db_engine)

    await _run(scan, _recon_with_run(site))

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert any("ffuf is not installed" in r for r in row.degraded_reasons)
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
            ("ffuf", "not_installed"),
        ]
        recon = {p.name: p for p in row.phases}[ScanPhaseName.RECON]
        assert recon.stats_json["dir_bruteforce"]["hosts_run"] == 0
    warn = [e for e in await _events(factory, scan.id) if e.stage == "dir_bruteforce"]
    assert warn and all(e.level == "warn" for e in warn)
    assert [p for p in site.paths if p.startswith("/sentinelcal")] == []


# --- Cancel ---------------------------------------------------------------------


@needs_ffuf
async def test_cancelling_during_ffuf_ends_the_scan_cancelled_and_leaves_no_process(
    db_engine, redis_client, make_site, monkeypatch
):
    import asyncio

    site = make_site(ls.planted_site())
    _patch_wordlist(monkeypatch, *WORDS, bulk=3000)  # 3000 requests at 10/s: far from done
    factory, scan, _ = await _scan(db_engine)

    async def press_cancel():
        for _ in range(300):
            if sum(1 for p in site.paths if p.startswith("/filler-")) >= 5:
                break
            await asyncio.sleep(0.1)
        await redis_client.set(cancel_key(scan.id), "dana", ex=120)

    presser = asyncio.ensure_future(press_cancel())
    started = time.monotonic()
    await asyncio.wait_for(_run(scan, _recon_with_run(site)), timeout=90)
    await presser
    assert time.monotonic() - started < 60

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
        assert runs["ffuf"].status == "cancelled"
        assert runs["ffuf"].skip_reason == "Cancelled by dana"
    assert "Scan cancelled by dana." in _messages(await _events(factory, scan.id), "scan")
    # no ffuf (or any of its children) is left running
    left = subprocess.run(["pgrep", "-f", "sentinel-ffuf-"], capture_output=True, text=True)
    assert left.stdout.strip() == ""
    # and the site stops hearing from us
    seen = len(site.requests)
    await asyncio.sleep(1.5)
    assert len(site.requests) == seen


# --- A step that goes wrong --------------------------------------------------------


async def test_a_crashing_step_costs_the_step_not_the_scan(
    db_engine, redis_client, make_site, monkeypatch
):
    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine)
    boom = AsyncMock(side_effect=RuntimeError("something broke"))
    with patch("sentinel_worker_app.scan_runner.run_dir_bruteforce", new=boom):
        await _run(scan, _recon_with_run(site))
    async with factory() as session:
        row = await session.get(Scan, scan.id)
        assert row.state == ScanState.COMPLETE
        assert any(
            "Directory brute force crashed and was skipped: RuntimeError: something broke" in r
            for r in row.degraded_reasons
        )
    assert any(
        e.level == "error" and e.stage == "dir_bruteforce" for e in await _events(factory, scan.id)
    )


async def test_a_database_error_in_the_step_is_recovered_from(
    db_engine, redis_client, make_site, monkeypatch
):
    """A failed flush leaves the session needing a rollback; the scan must go on."""
    import uuid

    site = make_site(ls.planted_site())
    factory, scan, _ = await _scan(db_engine)

    async def bad_step(session, scan_, *_args, **_kwargs):
        session.add(
            DiscoveredPath(
                scan_id=uuid.uuid4(),  # no such scan: the flush fails
                origin="x",
                path="/x",
                url="x",
                method="GET",
                status_code=200,
                category="common",
                wordlist="w",
                verdict="found",
            )
        )
        try:
            await session.flush()
        except IntegrityError:
            raise

    with patch("sentinel_worker_app.scan_runner.run_dir_bruteforce", new=bad_step):
        await _run(scan, _recon_with_run(site))
    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert any("Directory brute force crashed" in r for r in row.degraded_reasons)
        phases = {p.name: p for p in row.phases}
        assert phases[ScanPhaseName.RECON].status == PhaseStatus.COMPLETED
        assert phases[ScanPhaseName.REPORTING].status == PhaseStatus.COMPLETED
        # recon's own rows were committed before the step started and survived
        assert (
            await session.execute(select(ScanPhase).where(ScanPhase.scan_id == scan.id))
        ).first() is not None
