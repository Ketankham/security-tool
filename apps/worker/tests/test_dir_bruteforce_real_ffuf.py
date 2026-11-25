"""The step with the real ffuf, the real HttpEngine and local servers on
127.0.0.1: planted files are found and proven, hosts that answer everything
give nothing, excluded paths are never requested, and the guards hold.

Skipped when ``ffuf`` is not on PATH."""

from __future__ import annotations

import json
import shutil

import pytest
import sentinel_worker_test_fixture_dir_support as sup
import sentinel_worker_test_fixture_local_site as ls
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.enums import FindingConfidence
from sentinel_worker_app.passive_adapter import run_passive_and_verify

pytestmark = pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf is not installed")

PLANTED = (
    ("config", ".env"),
    ("config", ".env.local"),
    ("config", "config.json"),
    ("vcs", ".git/HEAD"),
    ("vcs", ".git/config"),
    ("admin", "admin"),
    ("admin", "admin/"),
    ("admin", "admin/login.php"),
    ("admin", "secret-area/x"),
    ("backup", "backup.zip"),
    ("backup", "old.zip"),
    ("backup", "dump.sql"),
    ("api", "api/"),
    ("api", "robots.txt"),
)


def _recon(site, host="127.0.0.1"):
    return sup.recon_for((host, site.port, "127.0.0.1"))


async def test_planted_secrets_are_found_proven_and_never_stored(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site(ls.planted_site())
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(*PLANTED),
        rules=[sup.rule("path_prefix", "/secret-area")],
    )
    assert result.error is None
    rows = {r.path: r for r in await result.rows()}
    assert set(rows) == {"/.env", "/.git/HEAD", "/admin/", "/backup.zip", "/robots.txt"}

    env, git, backup = rows["/.env"], rows["/.git/HEAD"], rows["/backup.zip"]
    assert (env.verdict, env.rule_id) == ("confirmed", "exposed.env_file")
    assert (git.verdict, git.rule_id) == ("confirmed", "exposed.git_repository")
    assert (backup.verdict, backup.rule_id, backup.method) == (
        "confirmed",
        "exposed.backup_file",
        "HEAD",
    )
    assert rows["/admin/"].verdict == "found" and rows["/admin/"].crawl_seed is True
    assert rows["/robots.txt"].verdict == "found" and not rows["/robots.txt"].crawl_seed
    assert env.category == "config" and git.category == "vcs" and backup.category == "backup"
    assert env.url == f"{site.origin}/.env" and env.origin == site.origin
    assert env.status_code == 200 and env.content_type.startswith("text/plain")
    assert result.stats.path_seeds == [f"{site.origin}/admin/"]

    # Confirmed means: a Finding whose Verification reproduced twice.
    findings = {f.rule_id: f for f in await result.findings()}
    assert set(findings) == {"exposed.env_file", "exposed.git_repository", "exposed.backup_file"}
    for finding in findings.values():
        assert finding.confidence is FindingConfidence.CONFIRMED
        assert finding.verification.reproduced_count == 2
        assert finding.verification.attempted_count == 2 and finding.verification.passed
        assert finding.evidence and finding.evidence[0].role == "exposed-file-response"
    assert env.finding_id == findings["exposed.env_file"].id

    # The evidence for the .env has no body, and the secret is nowhere in storage.
    env_evidence = findings["exposed.env_file"].evidence[0]
    store = LocalTranscriptStore(tmp_path / "transcripts")
    transcript = json.loads(await store.get(env_evidence.transcript_id))
    assert "body withheld" in transcript["response"]["body"]
    stored = await sup.everything_stored(db_engine, tmp_path / "transcripts")
    assert ls.ENV_SECRET not in stored
    assert "sk-live-0123456789abcdef" not in stored
    assert "hunter2secret" not in stored
    # ...but the variable names, which is what the finding says, are there.
    assert "DB_PASSWORD" in findings["exposed.env_file"].narrative
    assert "values not stored" in findings["exposed.env_file"].narrative

    # The excluded area and every other excluded path was never requested.
    assert not [p for p in site.paths if p.startswith("/secret-area")]
    # ffuf was pinned to the IP and sent the real name in Host.
    assert {r.host for r in site.requests} == {f"127.0.0.1:{site.port}"}
    # .env: baseline + ffuf + the check + two re-checks (GET), archive only by HEAD.
    assert not [r for r in site.requests if r.method == "GET" and r.path.endswith((".zip", ".sql"))]
    assert {r.path for r in site.requests if r.method == "HEAD"} >= {"/backup.zip", "/old.zip"}

    # The tool runs and the log.
    runs = await result.tool_runs()
    assert [(r.tool, r.status) for r in runs] == [("ffuf", "ok"), ("head-pass (built-in)", "ok")]
    assert '"FUZZ":"LmVudg' in runs[0].stdout  # ffuf's raw JSON lines are kept as written
    assert ls.ENV_SECRET not in runs[0].stdout  # ...and carry names and sizes, never content
    assert result.log.has("127.0.0.1: 5 path(s) found, 3 confirmed")
    assert result.log.has("entries removed by scope rules (e.g. /secret-area/x)")


async def test_an_exclude_rule_keeps_the_whole_prefix_and_the_calibration_off_the_wire(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site(ls.planted_site())
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(*PLANTED, ("admin", "administrator/"), ("admin", "adminer.php")),
        rules=[sup.rule("path_prefix", "/admin")],
    )
    assert result.error is None
    assert site.requests, "something must have been requested"
    assert not [p for p in site.paths if p.startswith("/admin")], site.paths
    assert not [p for p in site.paths if "admin" in p]  # ffuf's default admin<random> calibration
    assert "/admin/" not in {r.path for r in await result.rows()}


async def test_a_host_that_answers_everything_with_200_gives_no_rows(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site({}, ls.catch_all_page())
    result = await sup.run_step(
        db_engine, redis_client, tmp_path, _recon(site), sup.wordlist_loader(*PLANTED, bulk=60)
    )
    assert result.error is None
    assert await result.rows() == []
    assert await result.findings() == []
    assert result.log.has("a made-up path answers 200, so this host is a catch-all")
    assert result.log.has("127.0.0.1: 0 path(s) found, 0 confirmed")
    assert result.stats.hits == 0 and result.stats.confirmed == 0
    assert (await result.scan()).is_degraded is False


async def test_a_host_that_redirects_everything_to_login_gives_no_rows(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site({}, ls.redirect_everything())
    result = await sup.run_step(
        db_engine, redis_client, tmp_path, _recon(site), sup.wordlist_loader(*PLANTED, bulk=60)
    )
    assert result.error is None
    assert await result.rows() == []
    assert result.log.has("127.0.0.1: 0 path(s) found, 0 confirmed")


async def test_a_host_that_answers_429_is_stopped_and_the_scan_degraded(
    db_engine, redis_client, tmp_path, make_site
):
    # normal for the three baseline requests, then 429 for everything
    site = make_site({}, ls.rate_limit_after(3))
    result = await sup.run_step(
        db_engine, redis_client, tmp_path, _recon(site), sup.wordlist_loader(*PLANTED, bulk=120)
    )
    assert result.error is None
    (run, *rest) = await result.tool_runs()
    assert run.status == "stopped" and "429" in (run.skip_reason or "")
    assert rest == []  # no archive pass against a host that is rate limiting us
    assert result.stats.stopped_hosts == 1
    assert result.log.has("stopped: rate limited (429)")
    scan = await result.scan()
    assert scan.is_degraded and any("rate limited (429)" in r for r in scan.degraded_reasons)
    # it did not keep hammering: ffuf stops after about 50 requests
    assert len(site.requests) < 130
    assert await result.rows() == []


async def test_a_non_public_address_is_never_contacted_when_private_addresses_are_off(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site(ls.planted_site())
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(*PLANTED),
        allow_private=False,
    )
    assert result.error is None
    assert site.requests == []  # not a baseline request, not ffuf
    assert result.log.has("Not run: 127.0.0.1: it resolves to a non-public address (127.0.0.1)")
    assert await result.rows() == [] and await result.tool_runs() == []
    assert result.stats.hosts_planned == 0


async def test_the_engine_refuses_a_name_that_resolves_to_a_private_address_even_if_pinned_ok(
    db_engine, redis_client, tmp_path, make_site
):
    """Recon says the host is at a public address; the name actually resolves
    to loopback. ffuf would be pinned to the public IP, but the baseline goes by
    name through the engine, whose address guard refuses it: nothing is sent."""
    site = make_site(ls.planted_site())
    recon = sup.recon_for(("127.0.0.1", site.port, "93.184.216.34"))
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        recon,
        sup.wordlist_loader(*PLANTED),
        allow_private=True,  # the pinned-IP check passes ...
        engine_private=False,  # ... but the engine's own guard is on
    )
    assert site.requests == []
    assert result.log.has("the baseline requests did not succeed")
    assert await result.tool_runs() == []


async def test_a_signature_that_does_not_hold_up_is_not_confirmed(
    db_engine, redis_client, tmp_path, make_site
):
    # An "exposed" .env that is really an HTML page, and a Git HEAD that answers
    # correctly once and then not at all.
    calls = {".git/HEAD": 0}

    def decide(method, path, _host, _n):
        if path == "/.env":
            return ls.Reply(200, "<html><body>DB_PASSWORD=x\nAPI_KEY=y</body></html>")
        if path == "/.git/HEAD":
            calls[".git/HEAD"] += 1
            if calls[".git/HEAD"] <= 2:  # ffuf's request and the first check
                return ls.Reply(200, "ref: refs/heads/main\n", ctype="text/plain")
            return ls.Reply(404, "gone")
        return None

    site = make_site({}, decide)
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader((("config"), ".env"), ("vcs", ".git/HEAD")),
    )
    rows = {r.path: r for r in await result.rows()}
    assert rows["/.env"].verdict == "not_confirmed" and rows["/.env"].finding_id is None
    assert "does not look like" in rows["/.env"].note
    assert rows["/.git/HEAD"].verdict == "not_confirmed"
    assert "reproduced only 0 of 2" in rows["/.git/HEAD"].note
    assert await result.findings() == []
    assert result.stats.confirmed == 0 and result.stats.confirmed_fingerprints == set()


async def test_the_passive_check_does_not_report_a_file_the_brute_force_confirmed(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site(ls.planted_site())
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(*PLANTED),
        rules=[sup.rule("path_prefix", "/secret-area")],
    )
    assert len(result.stats.confirmed_fingerprints) == 3
    guard = sup.guard_for()
    engine = sup.make_engine(guard, redis_client, tmp_path, result.scan_id)
    scan = await result.scan()
    try:
        log = sup.RecordingLog()
        _stats, with_skip, _ = await run_passive_and_verify(
            scan=scan,
            fallback_origin=site.origin,
            surfaces=[],
            personas=[],
            in_memory_sessions={},
            http_engine=engine,
            scope_guard=guard,
            log=log,
            skip_fingerprints=result.stats.confirmed_fingerprints,
        )
        _stats2, without_skip, _ = await run_passive_and_verify(
            scan=scan,
            fallback_origin=site.origin,
            surfaces=[],
            personas=[],
            in_memory_sessions={},
            http_engine=engine,
            scope_guard=guard,
        )
    finally:
        await engine.aclose()
    rules_with = {f.rule_id for f in with_skip}
    rules_without = {f.rule_id for f in without_skip}
    assert {"exposed.env_file", "exposed.git_repository"} <= rules_without
    assert not {"exposed.env_file", "exposed.git_repository"} & rules_with
    assert log.has("already confirmed by directory brute force")
    # what the passive check alone found is untouched
    assert "headers.csp_missing" in rules_with


async def test_request_rate_stays_at_or_under_the_speed_setting(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site({}, None)
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(bulk=60),
        rps=20.0,
    )
    assert result.error is None
    times = sorted(r.at for r in site.requests if r.path.startswith("/filler-"))
    assert len(times) >= 55
    span = times[-1] - times[0]
    assert (len(times) - 1) / span <= 20.0 * 1.25  # measured from the server's own log
    # and in any one second never more than a little above the setting
    worst = max(sum(1 for t in times if t0 <= t < t0 + 1.0) for t0 in times)
    assert worst <= 20 * 1.5


async def test_two_hosts_run_one_at_a_time(db_engine, redis_client, tmp_path, make_site):
    first, second = make_site(ls.planted_site()), make_site(ls.planted_site())
    recon = sup.recon_for(
        ("127.0.0.1", first.port, "127.0.0.1"), ("localhost", second.port, "127.0.0.1")
    )
    result = await sup.run_step(
        db_engine, redis_client, tmp_path, recon, sup.wordlist_loader(*PLANTED)
    )
    assert result.stats.hosts_run == 2
    assert max(r.at for r in first.requests) < min(r.at for r in second.requests)
    assert {r.host for r in second.requests} == {f"localhost:{second.port}"}
    origins = {r.origin for r in await result.rows()}
    assert origins == {first.origin, f"http://localhost:{second.port}"}


async def test_a_template_env_file_is_listed_but_not_reported_as_a_secret(
    db_engine, redis_client, tmp_path, make_site
):
    site = make_site(
        {
            "/.env.example": ls.Reply(200, "DB_PASSWORD=changeme\nAPI_KEY=your-key-here\n"),
            "/.env": ls.Reply(200, ls.ENV_BODY, ctype="text/plain"),
        }
    )
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(("config", ".env"), ("config", ".env.example")),
    )
    rows = {r.path: r for r in await result.rows()}
    assert rows["/.env"].verdict == "confirmed"
    assert rows["/.env.example"].verdict == "found" and rows["/.env.example"].finding_id is None
    assert "template" in rows["/.env.example"].note
    assert site.count("/.env.example") == 1  # only ffuf's own request: never fetched again
    assert [f.rule_id for f in await result.findings()] == ["exposed.env_file"]


async def test_the_engine_requests_are_paced_too_not_just_ffufs(
    db_engine, redis_client, tmp_path, make_site
):
    """The HEAD pass and the re-checks go through the HttpEngine, whose limiter
    lets a burst through after a pause; the step spaces them out itself."""
    site = make_site({}, None)
    result = await sup.run_step(
        db_engine,
        redis_client,
        tmp_path,
        _recon(site),
        sup.wordlist_loader(*[("backup", f"b{i}.zip") for i in range(30)], ("config", "x.json")),
        rps=20.0,
    )
    assert result.error is None
    heads = sorted(r.at for r in site.requests if r.method == "HEAD")
    assert len(heads) >= 30
    worst = max(sum(1 for t in heads if t0 <= t < t0 + 1.0) for t0 in heads)
    assert worst <= 20 * 1.2  # the engine's own limiter (200/s here) would allow all 30 at once
