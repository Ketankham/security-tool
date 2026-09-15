"""SessionOracle against the real fixture server, through the real
HttpEngine — no mocked responses. Also exercises the persona_session
bridge: a PersonaSession built from a real LoginReplayer storage_state,
fed into the real scope-guarded rate-limited engine."""

from __future__ import annotations

from fakeredis.aioredis import FakeRedis
from sentinel_auth.models import Credential, LoginStep, SuccessAssertion
from sentinel_auth.models import LoginRecipe as _LoginRecipe
from sentinel_auth.oracle import establish_session_oracle
from sentinel_auth.persona_session import PersonaSession
from sentinel_auth.replay import LoginReplayer
from sentinel_core.http_engine import AnonymousSession, HttpEngine
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder


def _engine(tmp_path, login_server: str) -> HttpEngine:
    # ScopeGuard matches urlsplit(url).hostname, which never includes the
    # port — so the allowlist entry must not include it either.
    host = login_server.split("://", 1)[1].split(":")[0]
    scope_guard = ScopeGuard(allowed_hosts={host}, target_ownership_verified=True)
    rate_limiter = RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000)
    recorder = TranscriptRecorder(LocalTranscriptStore(tmp_path))
    return HttpEngine(
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        recorder=recorder,
        target_id="target-1",
        scan_id="scan-1",
    )


async def _logged_in_persona(login_server: str, browser) -> PersonaSession:
    replayer = LoginReplayer(browser)
    recipe = _LoginRecipe(
        start_url=f"{login_server}/login",
        steps=(
            LoginStep(action="fill", selector="input[name=username]", value="alice"),
            LoginStep(action="fill_secret", selector="input[name=password]", credential_ref="pw"),
            LoginStep(action="click", selector="button[type=submit]"),
        ),
        success_assertion=SuccessAssertion(kind="url_contains", value="/dashboard"),
    )
    result = await replayer.replay(
        recipe, credentials={"pw": Credential(ref="pw", secret="correct-horse-battery-staple")}
    )
    assert result.success
    # A cookie's `domain` is host-only (no port) — target_host must match
    # that, not the URL's host:port.
    host = login_server.split("://", 1)[1].split(":")[0]
    return PersonaSession("alice", result.storage_state, target_host=host)


async def test_establish_oracle_detects_status_code_differential(login_server, browser, tmp_path):
    persona = await _logged_in_persona(login_server, browser)
    engine = _engine(tmp_path, login_server)

    result = await establish_session_oracle(engine, persona, probe_url=f"{login_server}/api/me")

    assert result.oracle is not None
    assert result.oracle.signal == "status_code"
    assert result.oracle.authenticated_value == "200"
    await engine.aclose()


async def test_established_oracle_passes_for_authenticated_persona(login_server, browser, tmp_path):
    persona = await _logged_in_persona(login_server, browser)
    engine = _engine(tmp_path, login_server)

    result = await establish_session_oracle(engine, persona, probe_url=f"{login_server}/api/me")
    assert result.oracle is not None

    assert await result.oracle.check(engine, persona) is True
    await engine.aclose()


async def test_established_oracle_fails_for_anonymous_session(login_server, browser, tmp_path):
    persona = await _logged_in_persona(login_server, browser)
    engine = _engine(tmp_path, login_server)

    result = await establish_session_oracle(engine, persona, probe_url=f"{login_server}/api/me")
    assert result.oracle is not None

    anon = AnonymousSession()
    assert await result.oracle.check(engine, anon) is False
    await engine.aclose()


async def test_oracle_catches_session_death_mid_scan(login_server, browser, tmp_path):
    """The scenario docs/04-edge-cases.md §B1 warns about: prove the oracle
    actually notices when a session that *was* good stops being good."""
    persona = await _logged_in_persona(login_server, browser)
    engine = _engine(tmp_path, login_server)

    result = await establish_session_oracle(engine, persona, probe_url=f"{login_server}/api/me")
    assert result.oracle is not None
    assert await result.oracle.check(engine, persona) is True

    # Kill the session server-side (equivalent to it expiring mid-scan).
    await engine.request(
        "POST", f"{login_server}/logout", persona=persona, skip_destructive_guard=True
    )

    assert await result.oracle.check(engine, persona) is False
    await engine.aclose()


async def test_no_differential_found_returns_none_oracle(tmp_path):
    """docs/04 §B3: when the app gives us nothing to distinguish auth from
    anonymous, we must say so, not fabricate an oracle."""
    from fakeredis.aioredis import FakeRedis as _FakeRedis

    scope_guard = ScopeGuard(allowed_hosts={"example.test"}, target_ownership_verified=True)
    rate_limiter = RateLimiter(_FakeRedis(), default_rate_per_sec=1000, burst=1000)
    recorder = TranscriptRecorder(LocalTranscriptStore(tmp_path))
    engine = HttpEngine(
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        recorder=recorder,
        target_id="t",
        scan_id="s",
        client=_identical_response_client(),
    )
    persona = AnonymousSession()  # any persona works — the app itself never differentiates

    result = await establish_session_oracle(engine, persona, probe_url="https://example.test/")
    assert result.oracle is None
    assert "No reliable differential" in result.detail
    await engine.aclose()


def _identical_response_client():
    import httpx

    def handler(request):
        return httpx.Response(200, text="<html>same for everyone</html>")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))
