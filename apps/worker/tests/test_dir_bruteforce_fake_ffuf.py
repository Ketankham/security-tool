"""The step against a fake ``ffuf`` (a script on PATH) and a real HttpEngine and
local site: what it hands to ffuf, and how it behaves when ffuf misbehaves
(timeout, cancel, 429s, huge output, missing)."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import sentinel_worker_test_fixture_dir_support as sup
import sentinel_worker_test_fixture_local_site as ls
from sentinel_worker_app import dir_bruteforce_adapter as adapter
from sentinel_worker_app.cancel import ScanCancelled

SMALL = (
    ("config", ".env"),
    ("vcs", ".git/HEAD"),
    ("admin", "admin/"),
    ("admin", "admin/login.php"),
    ("backup", "backup.zip"),
    ("backup", "db.sql"),
    ("api", "api/v1/"),
    ("config", "config.json"),
)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie is gone as far as we are concerned
    try:
        return "Z" not in Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False


async def _wait_gone(pid: int, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        await asyncio.sleep(0.1)
    return not _alive(pid)


# A fake that reports `.env` (a 200 the site really serves) and `admin/`.
CANNED = """
emit(".env", 200, length=120, words=8, lines=4, ctype="text/plain")
emit("admin/", 200, length=40, words=5, lines=1)
"""


async def test_what_ffuf_is_given_is_scope_filtered_pinned_and_has_no_archives(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    capture = sup.install_fake_ffuf(tmp_path, monkeypatch, CANNED)
    recon = sup.recon_for(("127.0.0.1", site.port, "127.0.0.1"))
    # An exclude rule, and a destructive-looking name in the wordlist.
    loader = sup.wordlist_loader(*SMALL, ("admin", "user/logout"), ("api", "private/keys"))
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        recon,
        loader,
        rules=[sup.rule("path_prefix", "/admin"), sup.rule("path_regex", r"^/private/")],
    )
    assert result.error is None
    sent = (capture / "wordlist.txt").read_text().split("\n")
    # only paths that passed the scope guard and the destructive screen
    assert sorted(sent) == [".env", ".git/HEAD", "api/v1/", "config.json"]
    assert not any(p.startswith("admin") or p.startswith("private") for p in sent)
    assert "user/logout" not in sent
    # (b) archives never go to ffuf
    assert "backup.zip" not in sent and "db.sql" not in sent
    args = json.loads((capture / "args.json").read_text())
    assert args[args.index("-u") + 1] == f"http://127.0.0.1:{site.port}/FUZZ"  # pinned to the IP
    assert f"Host: 127.0.0.1:{site.port}" in args
    assert "-sni" not in args  # plain http
    assert "-ac" in args and args.count("-acc") >= 3
    for forbidden in (
        "-recursion",
        "-r",
        "-X",
        "-d",
        "-input-cmd",
        "-od",
        "-audit-log",
        "-preflight",
    ):
        assert forbidden not in args
    assert args[args.index("-rate") + 1] == "50"
    assert "-sa" in args and "-maxtime" in args
    cal = [args[i + 1] for i, a in enumerate(args) if a == "-acc"]
    assert all(c.startswith(("sentinelcal", ".sentinelcal")) for c in cal)
    # ffuf runs in its own private directory, which is gone afterwards
    cwd, home = (capture / "cwd").read_text().split("\n")
    assert cwd == home and "sentinel-ffuf-" in cwd and not Path(cwd).exists()
    # the stats say what was removed
    assert result.stats.entries_removed_by_scope >= 3
    assert result.log.has("entries removed by scope rules")
    assert result.log.has("removed by the destructive-action screen")
    # nothing under /admin or /private, nor the destructive names, was ever requested
    assert not [p for p in site.paths if p.startswith(("/admin", "/private", "/user"))]


async def test_canned_hits_become_rows_and_a_confirmed_finding(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    sup.install_fake_ffuf(tmp_path, monkeypatch, CANNED)
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
        seq=4,
    )
    assert result.error is None
    rows = {r.path: r for r in await result.rows()}
    assert rows["/.env"].verdict == "confirmed" and rows["/.env"].rule_id == "exposed.env_file"
    assert rows["/.env"].finding_id is not None and rows["/.env"].method == "GET"
    assert rows["/admin/"].verdict == "found" and rows["/admin/"].crawl_seed is True
    # the archive was checked by HEAD through the engine, not by ffuf
    assert rows["/backup.zip"].method == "HEAD" and rows["/backup.zip"].verdict == "confirmed"
    assert rows["/backup.zip"].content_length == 4096
    assert "/db.sql" not in rows  # 404 on HEAD: nothing recorded
    runs = await result.tool_runs()
    assert [(r.seq, r.tool, r.status) for r in runs] == [
        (4, "ffuf", "ok"),
        (5, "head-pass (built-in)", "ok"),
    ]
    assert "# wordlist sentinel-core sha256 " + "ab" * 32 in runs[0].command
    assert "HEAD http://127.0.0.1" in runs[1].stdout and "backup.zip" in runs[1].stdout
    assert rows["/.env"].tool_run_id == runs[0].id and rows["/backup.zip"].tool_run_id == runs[1].id
    assert result.stats.hosts_planned == result.stats.hosts_run == 1
    assert result.stats.hits == 3 and result.stats.confirmed == 2
    assert result.log.has("127.0.0.1: 3 path(s) found, 2 confirmed")
    assert result.log.has("Directory brute force on 1 host(s) with sentinel-core (8 entries")
    assert result.log.has("Authorised by alice.")
    assert result.log.has("Running: ffuf ")


async def test_a_hit_that_is_not_in_the_wordlist_is_never_recorded(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    sup.install_fake_ffuf(
        tmp_path, monkeypatch, 'emit("/secret-area/x"); emit("sentinelcalabc123"); emit(".env")'
    )
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader((("config"), ".env")),
    )
    assert [r.path for r in await result.rows()] == ["/.env"]


async def test_ffuf_that_never_finishes_times_out_and_is_killed(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    capture = sup.install_fake_ffuf(tmp_path, monkeypatch, "time.sleep(300)")
    monkeypatch.setattr(adapter, "SUBPROCESS_GRACE_S", 0)
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
        host_cap_s=1,
    )
    assert result.error is None
    (run, *_) = await result.tool_runs()
    assert run.tool == "ffuf" and run.status == "timed_out" and run.timed_out is True
    assert result.stats.stopped_hosts == 1
    scan = await result.scan()
    assert scan.is_degraded and any("timed out" in r for r in scan.degraded_reasons)
    pid = int((capture / "pid").read_text())
    assert await _wait_gone(pid)


async def test_cancelling_mid_run_kills_ffuf_and_keeps_what_ran(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    capture = sup.install_fake_ffuf(tmp_path, monkeypatch, "time.sleep(300)")
    cancel = sup.FakeCancel()

    async def press():
        for _ in range(100):
            if (capture / "pid").exists():
                break
            await asyncio.sleep(0.05)
        cancel.by = "dana"

    presser = asyncio.ensure_future(press())
    result = await asyncio.wait_for(
        sup.run_step(
            db_engine,
            redis_client,
            tmp_path,
            sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
            sup.wordlist_loader(*SMALL),
            cancel=cancel,
        ),
        timeout=30,
    )
    await presser
    assert isinstance(result.error, ScanCancelled) and result.error.by == "dana"
    assert await _wait_gone(int((capture / "pid").read_text()))
    (run,) = await result.tool_runs()  # committed before the cancel ended the step
    assert run.status == "cancelled" and run.skip_reason == "Cancelled by dana"


async def test_cancel_between_hosts_stops_before_the_next_host(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    first, second = make_site(ls.planted_site()), make_site(ls.planted_site())
    sup.install_fake_ffuf(tmp_path, monkeypatch, CANNED)
    cancel = sup.FakeCancel()

    def on_add(_stage, _level, message):
        if message.startswith("127.0.0.1: ") and "path(s) found" in message:
            cancel.by = "erin"  # the first host is done

    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(
            ("127.0.0.1", first.port, "127.0.0.1"), ("localhost", second.port, "127.0.0.1")
        ),
        sup.wordlist_loader(*SMALL),
        cancel=cancel,
        log=sup.RecordingLog(on_add),
    )
    assert isinstance(result.error, ScanCancelled) and result.error.by == "erin"
    assert second.requests == []  # the second host was never touched
    assert {r.path for r in await result.rows()} >= {"/.env"}  # the first host's rows were kept


async def test_a_429_stream_stops_the_host_and_marks_the_run_stopped(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    capture = sup.install_fake_ffuf(
        tmp_path,
        monkeypatch,
        """
for p in paths[:8]:
    emit(p, 429, length=3, words=1, lines=1)
time.sleep(300)
""",
    )
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
    )
    (run, *rest) = await result.tool_runs()
    assert run.status == "stopped" and "pushed back" in (run.skip_reason or "")
    assert rest == []  # no HEAD pass against a host that is pushing back
    assert result.stats.stopped_hosts == 1
    assert await _wait_gone(int((capture / "pid").read_text()))
    assert await result.rows() == []
    assert result.log.has("stopped: the host pushed back")
    scan = await result.scan()
    assert scan.is_degraded and any("stopped early" in r for r in scan.degraded_reasons)


async def test_two_hosts_in_a_row_pushing_back_stop_the_whole_step(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    sites = [make_site(ls.planted_site()) for _ in range(3)]
    sup.install_fake_ffuf(
        tmp_path,
        monkeypatch,
        """
for p in paths[:8]:
    emit(p, 429, length=3, words=1, lines=1)
time.sleep(300)
""",
    )
    recon = sup.recon_for(
        ("127.0.0.1", sites[0].port, "127.0.0.1"),
        ("localhost", sites[1].port, "127.0.0.1"),
        ("runsc", sites[2].port, "127.0.0.1"),
    )
    result = await sup.run_step(
        db_engine, redis_client, tmp_path, recon, sup.wordlist_loader(*SMALL)
    )
    assert result.stats.stopped_hosts == 2 and result.stats.hosts_run == 2
    assert result.stats.not_run_hosts == 1
    assert [r.tool for r in await result.tool_runs()] == ["ffuf", "ffuf"]
    assert not [r for r in sites[2].requests]  # the third host was never touched
    assert result.log.has("Not run: runsc")
    scan = await result.scan()
    assert any("two hosts in a row" in r for r in scan.degraded_reasons)


async def test_one_pushed_back_host_does_not_stop_the_next(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    first, second = make_site(ls.planted_site()), make_site(ls.planted_site())
    sup.install_fake_ffuf(
        tmp_path,
        monkeypatch,
        f"""
if "Host: 127.0.0.1:{first.port}" in args:
    for p in paths[:8]:
        emit(p, 429, length=3, words=1, lines=1)
    time.sleep(300)
emit(".env", 200, length=120, words=8, lines=4, ctype="text/plain")
""",
    )
    recon = sup.recon_for(
        ("127.0.0.1", first.port, "127.0.0.1"), ("localhost", second.port, "127.0.0.1")
    )
    result = await sup.run_step(
        db_engine, redis_client, tmp_path, recon, sup.wordlist_loader(*SMALL)
    )
    assert result.stats.stopped_hosts == 1 and result.stats.hosts_run == 2
    assert result.stats.not_run_hosts == 0
    confirmed = [r for r in await result.rows() if r.verdict == "confirmed"]
    assert {(r.origin, r.path) for r in confirmed} >= {(f"http://localhost:{second.port}", "/.env")}


async def test_ffuf_stderr_stop_message_is_reported_as_a_stop(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    sup.install_fake_ffuf(
        tmp_path,
        monkeypatch,
        'sys.stderr.write("Getting an unusual amount of 429 responses, exiting.\\n")',
    )
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
    )
    assert result.stats.stopped_hosts == 1
    assert result.log.has("stopped: rate limited (429)")
    (run, *_) = await result.tool_runs()
    assert "unusual amount of 429" in run.stderr


async def test_huge_output_is_stored_cut_off(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    sup.install_fake_ffuf(
        tmp_path,
        monkeypatch,
        """
line = "x" * 1000
for _ in range(3000):
    print(line)
emit(".env", 200, length=120, words=8, lines=4, ctype="text/plain")
""",
    )
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
    )
    (run, *_) = await result.tool_runs()
    assert run.stdout_truncated is True and len(run.stdout) == 512_000
    # ...and the hit after 3 MB of noise was still seen
    assert "/.env" in [r.path for r in await result.rows()]


async def test_ffuf_exiting_with_an_error_degrades_the_scan(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    sup.install_fake_ffuf(
        tmp_path, monkeypatch, 'sys.stderr.write("bad flag provided\\n"); sys.exit(2)'
    )
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
    )
    (run, *_) = await result.tool_runs()
    assert run.status == "failed" and run.exit_code == 2
    scan = await result.scan()
    assert any(
        "ffuf failed on 127.0.0.1 (exit code 2): bad flag provided" in r
        for r in scan.degraded_reasons
    )


async def test_a_missing_ffuf_skips_the_step_with_a_warning_and_a_degraded_reason(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
    )
    assert result.error is None
    (run,) = await result.tool_runs()
    assert run.tool == "ffuf" and run.status == "not_installed"
    assert "not installed" in (run.skip_reason or "")
    assert await result.rows() == []
    assert site.requests == []  # not even a baseline request
    assert ("dir_bruteforce", "warn") in {(s, lvl) for s, lvl, _m in result.log.lines}
    assert result.log.has("ffuf is not installed on the worker")
    scan = await result.scan()
    assert scan.is_degraded and any("ffuf is not installed" in r for r in scan.degraded_reasons)
    assert result.stats.hosts_run == 0 and result.stats.not_run_hosts == 1


async def test_the_time_budget_stops_the_step_and_names_the_hosts_not_run(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    first, second = make_site(ls.planted_site()), make_site(ls.planted_site())
    sup.install_fake_ffuf(tmp_path, monkeypatch, CANNED)
    now = [1000.0]

    def clock() -> float:
        return now[0]

    def on_add(_stage, _level, message):
        if message.startswith("127.0.0.1: ") and "path(s) found" in message:
            now[0] += 595  # the first host used almost the whole 600 s budget

    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(
            ("127.0.0.1", first.port, "127.0.0.1"), ("localhost", second.port, "127.0.0.1")
        ),
        sup.wordlist_loader(*SMALL),
        budget_s=600,
        clock=clock,
        log=sup.RecordingLog(on_add),
    )
    assert result.stats.hosts_run == 1 and result.stats.not_run_hosts == 1
    assert second.requests == []
    assert result.log.has("Not run: localhost (time budget).")
    scan = await result.scan()
    assert any("ran out of time" in r and "localhost" in r for r in scan.degraded_reasons)


async def test_the_per_host_time_limit_is_the_smaller_of_the_cap_and_what_is_left(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    capture = sup.install_fake_ffuf(tmp_path, monkeypatch, "")
    await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
        budget_s=100,
        host_cap_s=900,
    )
    args = json.loads((capture / "args.json").read_text())
    assert 95 <= int(args[args.index("-maxtime") + 1]) <= 100
    await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
        budget_s=5000,
        host_cap_s=900,
    )
    args = json.loads((capture / "args.json").read_text())
    assert int(args[args.index("-maxtime") + 1]) == 900


async def test_seclists_that_is_missing_falls_back_to_the_core_list_and_says_so(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site(ls.planted_site())
    sup.install_fake_ffuf(tmp_path, monkeypatch, "")
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader((("config"), ".env")),
        wordlist_name="seclists-common",
    )
    assert result.stats.wordlist == "sentinel-core"
    assert result.log.has("The seclists-common wordlist is not available in this build")


async def test_a_pre_start_429_skips_the_host_as_rate_limited(
    db_engine, redis_client, tmp_path, monkeypatch, make_site
):
    site = make_site({}, ls.rate_limit_after(0))
    capture = sup.install_fake_ffuf(tmp_path, monkeypatch, "")
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        sup.recon_for(("127.0.0.1", site.port, "127.0.0.1")),
        sup.wordlist_loader(*SMALL),
    )
    assert result.log.has("rate limited before start")
    assert not (capture / "args.json").exists()  # ffuf was never started
    assert result.stats.stopped_hosts == 1 and result.stats.hosts_run == 0
