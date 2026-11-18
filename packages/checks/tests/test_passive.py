"""Passive/config checks against simulated sites: a deliberately vulnerable
one (every check must fire, with evidence that can be verified) and a
hardened one (no false alarms). Requests go through the real HttpEngine
(scope guard, rate limiter, transcript recording) over httpx.MockTransport."""

from __future__ import annotations

import httpx
import pytest
from fakeredis.aioredis import FakeRedis
from sentinel_checks.passive import PassiveContext, run_passive_checks
from sentinel_checks.passive import tls as tls_module
from sentinel_checks.passive.cookies import check_cookies, is_session_like, parse_set_cookie
from sentinel_checks.passive.headers import RULES, check_security_headers
from sentinel_checks.verification import verify_candidate
from sentinel_core.http_engine import HttpEngine
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder

ORIGIN = "https://shop.test"
HTML = "<html><body><h1>Shop</h1></body></html>"


def make_ctx(tmp_path, handler, *, origins=(ORIGIN,), pages=None, apis=None, personas=None):
    engine = HttpEngine(
        scope_guard=ScopeGuard(
            allowed_hosts={"shop.test", "*.shop.test"}, target_ownership_verified=True
        ),
        rate_limiter=RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000),
        recorder=TranscriptRecorder(LocalTranscriptStore(tmp_path)),
        target_id="t",
        scan_id="s",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    logs: list[tuple[str, str]] = []
    ctx = PassiveContext(
        http=engine,
        origins=list(origins),
        pages_by_origin=pages or {o: [f"{o}/"] for o in origins},
        api_urls_by_origin=apis or {},
        persona_cookies=personas or {},
        log=lambda level, message: logs.append((level, message)),
    )
    return ctx, logs, TranscriptRecorder(LocalTranscriptStore(tmp_path))


def vulnerable_site(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if request.url.scheme == "http":
        return httpx.Response(200, html=HTML)  # no redirect to https
    if path == "/":
        return httpx.Response(
            200,
            headers=[
                ("content-type", "text/html"),
                ("server", "Apache/2.4.41 (Ubuntu)"),
                ("x-powered-by", "PHP/7.4.3"),
                ("set-cookie", "sessionid=abc123; Path=/"),
                ("set-cookie", "theme=dark; Path=/; Secure; HttpOnly"),
            ],
            content=HTML,
        )
    if path == "/api/data":
        origin = request.headers.get("origin")
        headers = (
            {"access-control-allow-origin": origin, "access-control-allow-credentials": "true"}
            if origin
            else {}
        )
        return httpx.Response(200, json={"ok": 1}, headers=headers)
    if path == "/.env":
        return httpx.Response(
            200, text="DB_HOST=localhost\nDB_PASSWORD=hunter2hunter2\nAPP_KEY=base64:abcdef\n"
        )
    if path == "/.git/HEAD":
        return httpx.Response(200, text="ref: refs/heads/main\n")
    if path == "/openapi.json":
        return httpx.Response(200, json={"openapi": "3.0.0", "paths": {"/a": {}, "/b": {}}})
    if path == "/backup.zip":
        return httpx.Response(
            200, content=b"PK\x03\x04" + b"0" * 5000, headers={"content-type": "application/zip"}
        )
    # Catch-all: every other path "works" (a soft 404). Probes must not be
    # fooled by it.
    return httpx.Response(200, html="<html><body>Welcome back!</body></html>")


def hardened_site(request: httpx.Request) -> httpx.Response:
    if request.url.scheme == "http":
        return httpx.Response(301, headers={"location": "https://shop.test/"})
    if request.url.path == "/":
        return httpx.Response(
            200,
            headers=[
                ("content-type", "text/html"),
                ("strict-transport-security", "max-age=63072000; includeSubDomains"),
                ("content-security-policy", "default-src 'self'; frame-ancestors 'self'"),
                ("x-content-type-options", "nosniff"),
                ("referrer-policy", "strict-origin-when-cross-origin"),
                ("permissions-policy", "camera=()"),
                ("server", "nginx"),
                ("set-cookie", "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ],
            content=HTML,
        )
    return httpx.Response(404, text="not found")


@pytest.fixture(autouse=True)
def no_real_tls(monkeypatch):
    """The engine-level tests must not open real sockets to shop.test."""

    async def unreachable(host, port, context_factory=None):
        return {"status": "ok", "days_left": 200.0, "version": "TLSv1.3"}

    async def no_legacy(host, port):
        return []

    monkeypatch.setattr(tls_module, "probe_certificate", unreachable)
    monkeypatch.setattr(tls_module, "legacy_protocols_accepted", no_legacy)


# --- the vulnerable site: everything fires -----------------------------------


async def test_a_vulnerable_site_is_flagged_by_every_check(tmp_path):
    ctx, logs, _ = make_ctx(tmp_path, vulnerable_site, apis={ORIGIN: [f"{ORIGIN}/api/data"]})
    result = await run_passive_checks(ctx)
    rules = {c.rule_id for c in result.candidates}

    assert {
        "headers.hsts_missing",
        "headers.csp_missing",
        "headers.clickjacking",
        "headers.nosniff_missing",
        "headers.referrer_policy_missing",
        "headers.permissions_policy_missing",
        "headers.version_disclosure",
        "cookies.missing_secure",
        "cookies.missing_httponly",
        "cors.reflected_origin_credentials",
        "exposed.env_file",
        "exposed.git_repository",
        "exposed.api_docs",
        "exposed.backup_file",
        "tls.no_https_redirect",
    } <= rules
    assert not result.failed
    assert result.requests > 20

    # The soft-404 catch-all must not create exposed-file findings.
    exposed = {c.subject for c in result.candidates if c.rule_id.startswith("exposed.")}
    assert exposed == {"/.env", "/.git/HEAD", "/openapi.json", "/backup.zip"}

    # Severity and shape.
    by_rule = {c.rule_id: c for c in result.candidates}
    assert by_rule["exposed.env_file"].severity == "critical"
    assert by_rule["cors.reflected_origin_credentials"].severity == "high"
    assert by_rule["cookies.missing_httponly"].severity == "medium"
    assert by_rule["headers.version_disclosure"].severity == "info"
    for c in result.candidates:
        assert c.remediation_summary and c.remediation_steps and c.reproduction_curl
        assert c.narrative and c.origin == ORIGIN

    # Only the session cookie is blamed; the theme cookie is fine.
    assert "sessionid" in by_rule["cookies.missing_httponly"].narrative
    assert "theme" not in by_rule["cookies.missing_httponly"].narrative

    assert any("Exposed file" in message for _, message in logs)


async def test_every_reproducible_candidate_is_confirmed_on_recheck(tmp_path):
    ctx, _, _ = make_ctx(tmp_path, vulnerable_site, apis={ORIGIN: [f"{ORIGIN}/api/data"]})
    result = await run_passive_checks(ctx)
    checked = 0
    for candidate in result.candidates:
        assert candidate.reproduce is not None, candidate.rule_id
        outcome = await verify_candidate(candidate.reproduce)
        assert outcome.passed, candidate.rule_id
        checked += 1
    assert checked == len(result.candidates)


async def test_a_fixed_problem_no_longer_reproduces(tmp_path):
    state = {"fixed": False}

    def site(request):
        if state["fixed"] and request.url.path == "/.git/HEAD":
            return httpx.Response(404)
        return vulnerable_site(request)

    ctx, _, _ = make_ctx(tmp_path, site)
    result = await run_passive_checks(ctx)
    git = next(c for c in result.candidates if c.rule_id == "exposed.git_repository")
    state["fixed"] = True
    assert not (await verify_candidate(git.reproduce)).passed


async def test_secrets_in_exposed_files_are_never_stored_or_quoted(tmp_path):
    ctx, _, recorder = make_ctx(tmp_path, vulnerable_site)
    result = await run_passive_checks(ctx)
    env = next(c for c in result.candidates if c.rule_id == "exposed.env_file")
    stored = await recorder.load(env.evidence[0].transcript_id)
    assert "hunter2hunter2" not in str(stored)
    assert "body withheld" in stored["response"]["body"]
    assert stored["response"]["status_code"] == 200
    # Variable names help the reader; values never appear anywhere.
    assert "DB_PASSWORD" in env.narrative or "DB_HOST" in env.narrative
    assert "hunter2hunter2" not in env.narrative + env.reproduction_curl


async def test_a_backup_is_recognised_without_downloading_it(tmp_path):
    methods = []

    def site(request):
        if request.url.path == "/backup.zip":
            methods.append(request.method)
        return vulnerable_site(request)

    ctx, _, _ = make_ctx(tmp_path, site)
    await run_passive_checks(ctx)
    assert methods and set(methods) == {"HEAD"}


# --- the hardened site: no false alarms --------------------------------------


async def test_a_hardened_site_produces_no_findings(tmp_path):
    ctx, _, _ = make_ctx(tmp_path, hardened_site, apis={ORIGIN: [f"{ORIGIN}/api/data"]})
    result = await run_passive_checks(ctx)
    assert [c.rule_id for c in result.candidates] == []
    assert not result.failed


# --- header rules (pure predicates) -------------------------------------------


def violated(headers: dict[str, str]) -> set[str]:
    return {r.rule_id for r in RULES if r.violates(headers)}


def test_header_rules_judge_each_header_independently():
    assert "headers.csp_missing" in violated({})
    assert "headers.csp_missing" not in violated({"Content-Security-Policy": "default-src 'self'"})
    assert "headers.csp_report_only" in violated({"Content-Security-Policy-Report-Only": "x"})
    assert "headers.csp_missing" not in violated({"Content-Security-Policy-Report-Only": "x"})
    assert "headers.clickjacking" in violated({})
    assert "headers.clickjacking" not in violated({"X-Frame-Options": "DENY"})
    assert "headers.clickjacking" not in violated(
        {"Content-Security-Policy": "frame-ancestors 'none'"}
    )
    assert "headers.nosniff_missing" not in violated({"x-content-type-options": "nosniff"})
    assert "headers.hsts_weak" in violated({"strict-transport-security": "max-age=300"})
    assert "headers.hsts_weak" not in violated({"strict-transport-security": "max-age=31536000"})
    assert "headers.hsts_weak" not in violated({})  # absence is the other rule
    assert "headers.version_disclosure" in violated({"Server": "nginx/1.18.0"})
    assert "headers.version_disclosure" not in violated({"Server": "nginx"})


async def test_hsts_is_only_judged_on_https_sites(tmp_path):
    def site(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=HTML)

    ctx, _, _ = make_ctx(tmp_path, site, origins=("http://shop.test",))
    rules = {c.rule_id for c in await check_security_headers(ctx)}
    assert "headers.hsts_missing" not in rules
    assert "headers.csp_missing" in rules


async def test_redirects_and_error_pages_are_not_judged(tmp_path):
    def site(request):
        return httpx.Response(302, headers={"location": "https://www.shop.test/"})

    ctx, logs, _ = make_ctx(tmp_path, site)
    assert await check_security_headers(ctx) == []
    assert any("could not be judged" in m for _, m in logs)


async def test_a_header_missing_on_some_pages_lists_those_pages(tmp_path):
    def site(request):
        headers = {"content-type": "text/html"}
        if request.url.path == "/good":
            headers["content-security-policy"] = "default-src 'self'"
        return httpx.Response(200, headers=headers, content=HTML)

    pages = {ORIGIN: [f"{ORIGIN}/good", f"{ORIGIN}/bad1", f"{ORIGIN}/bad2"]}
    ctx, _, _ = make_ctx(tmp_path, site, pages=pages)
    csp = next(c for c in await check_security_headers(ctx) if c.rule_id == "headers.csp_missing")
    assert "2 of 3 page(s)" in csp.narrative
    assert "/bad1" in csp.narrative and "/good" not in csp.narrative


# --- cookies ---------------------------------------------------------------------


def test_cookie_parsing_and_session_detection():
    cookie = parse_set_cookie("sessionid=abc; Path=/; Secure; HttpOnly; SameSite=None")
    assert (cookie.name, cookie.secure, cookie.http_only, cookie.same_site) == (
        "sessionid",
        True,
        True,
        "none",
    )
    bare = parse_set_cookie("theme=dark")
    assert not bare.secure and not bare.http_only and bare.same_site is None
    assert parse_set_cookie("garbage") is None
    assert is_session_like("PHPSESSID") and is_session_like("auth_token")
    assert not is_session_like("theme") and not is_session_like("csrftoken")


async def test_cookies_after_login_are_probable_and_never_carry_values(tmp_path):
    def site(request):
        return httpx.Response(200)

    personas = {
        "Teacher": [
            {
                "name": "sid",
                "value": "SECRETVALUE",
                "domain": "shop.test",
                "secure": False,
                "httpOnly": False,
                "sameSite": "Lax",
            },
            {
                "name": "theme",
                "value": "dark",
                "domain": "shop.test",
                "secure": True,
                "httpOnly": False,
                "sameSite": "Lax",
            },
            {
                "name": "other",
                "value": "x",
                "domain": "elsewhere.test",
                "secure": False,
                "httpOnly": False,
                "sameSite": "Lax",
            },
        ]
    }
    ctx, _, _ = make_ctx(tmp_path, site, personas=personas)
    found = await check_cookies(ctx)
    rules = {c.rule_id for c in found}
    assert rules == {"cookies.missing_secure", "cookies.missing_httponly"}
    for c in found:
        assert c.reproduce is None  # seen once: stays probable
        assert "SECRETVALUE" not in c.narrative + c.reproduction_curl
        assert "Teacher" in c.narrative
        assert "elsewhere" not in c.narrative
    secure = next(c for c in found if c.rule_id == "cookies.missing_secure")
    assert secure.severity == "medium"  # a session cookie without Secure


# --- CORS --------------------------------------------------------------------------


async def test_cors_without_credentials_is_low_and_only_for_api_endpoints(tmp_path):
    def site(request):
        origin = request.headers.get("origin", "")
        return httpx.Response(
            200,
            headers={"access-control-allow-origin": origin, "content-type": "text/html"},
            content=HTML,
        )

    from sentinel_checks.passive.cors import check_cors

    ctx, _, _ = make_ctx(tmp_path, site, apis={ORIGIN: [f"{ORIGIN}/api/x"]})
    found = await check_cors(ctx)
    assert [c.rule_id for c in found] == ["cors.reflected_origin"]
    assert found[0].severity == "low"
    assert "/api/x" in found[0].narrative and f"{ORIGIN}/ " not in found[0].narrative


async def test_a_fixed_origin_allow_list_is_not_flagged(tmp_path):
    def site(request):
        return httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "https://app.shop.test",
                "access-control-allow-credentials": "true",
            },
            json={},
        )

    from sentinel_checks.passive.cors import check_cors

    ctx, _, _ = make_ctx(tmp_path, site, apis={ORIGIN: [f"{ORIGIN}/api/x"]})
    assert await check_cors(ctx) == []


# --- robustness -----------------------------------------------------------------------


async def test_unreachable_hosts_and_out_of_scope_urls_are_logged_not_fatal(tmp_path):
    def site(request):
        raise httpx.ConnectError("boom")

    ctx, logs, _ = make_ctx(tmp_path, site, pages={ORIGIN: ["https://evil.example/"]})
    result = await run_passive_checks(ctx)
    assert result.candidates == [] or all(c.rule_id.startswith("tls.") for c in result.candidates)
    assert not result.failed
    assert any(level == "warn" for level, _ in logs)


async def test_a_dead_host_is_not_probed_over_and_over(tmp_path):
    calls = {"n": 0}

    def site(request):
        calls["n"] += 1
        raise httpx.ConnectError("down")

    ctx, logs, _ = make_ctx(tmp_path, site)
    result = await run_passive_checks(ctx)
    assert result.candidates == []
    assert ORIGIN in ctx.unreachable
    # A few page fetches (with their retries), not ~20 file probes each retried.
    assert calls["n"] < 15
    assert any("did not answer" in m for _, m in logs)


async def test_a_crashing_check_is_isolated(tmp_path, monkeypatch):
    from sentinel_checks.passive import engine as engine_module

    async def broken(ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        engine_module,
        "CHECKS",
        [("broken", broken), *[c for c in engine_module.CHECKS if c[0] == "cookies"]],
    )
    ctx, logs, _ = make_ctx(tmp_path, hardened_site)
    result = await run_passive_checks(ctx)
    assert "broken" in result.failed and "boom" in result.failed["broken"]
    assert "cookies" in result.per_check
    assert any(level == "error" and "crashed" in m for level, m in logs)
