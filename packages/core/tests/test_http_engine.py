import httpx
import pytest
from fakeredis.aioredis import FakeRedis
from sentinel_core.http_engine import HttpEngine, ScopeViolation
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import DestructiveActionGuard, ScopeGuard
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder


def make_engine(tmp_path, *, handler, allowed_hosts=None, read_write_enabled=False):
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, follow_redirects=False)
    scope_guard = ScopeGuard(
        allowed_hosts=allowed_hosts or {"app.acme.test"}, target_ownership_verified=True
    )
    rate_limiter = RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000)
    recorder = TranscriptRecorder(LocalTranscriptStore(tmp_path))
    destructive_guard = DestructiveActionGuard(read_write_enabled=read_write_enabled)
    return HttpEngine(
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        recorder=recorder,
        destructive_guard=destructive_guard,
        target_id="target-1",
        scan_id="scan-1",
        client=client,
    )


async def test_successful_get_returns_response_and_transcript(tmp_path):
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    engine = make_engine(tmp_path, handler=handler)
    resp = await engine.request("GET", "https://app.acme.test/api/me")
    assert resp.status_code == 200
    assert resp.transcript_id  # non-empty
    assert '"ok": true' in resp.text.lower() or '"ok":true' in resp.text.lower()


async def test_out_of_scope_host_raises_and_makes_no_request(tmp_path):
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200)

    engine = make_engine(tmp_path, handler=handler)
    with pytest.raises(ScopeViolation):
        await engine.request("GET", "https://evil.example/steal")
    assert called["n"] == 0


async def test_destructive_post_blocked_by_default(tmp_path):
    def handler(request):
        return httpx.Response(200)

    engine = make_engine(tmp_path, handler=handler, read_write_enabled=False)
    with pytest.raises(ScopeViolation):
        await engine.request("POST", "https://app.acme.test/api/comments", body=b"{}")


async def test_destructive_post_allowed_when_read_write_enabled(tmp_path):
    def handler(request):
        return httpx.Response(201)

    engine = make_engine(tmp_path, handler=handler, read_write_enabled=True)
    resp = await engine.request("POST", "https://app.acme.test/api/comments", body=b"{}")
    assert resp.status_code == 201


async def test_persona_cookies_and_headers_are_sent(tmp_path):
    captured = {}

    def handler(request):
        captured["cookie"] = request.headers.get("cookie")
        captured["x-custom"] = request.headers.get("x-custom")
        return httpx.Response(200)

    class FakePersona:
        persona_id = "admin"

        def cookies(self):
            return {"sid": "abc123"}

        def extra_headers(self):
            return {"X-Custom": "yes"}

    engine = make_engine(tmp_path, handler=handler)
    await engine.request("GET", "https://app.acme.test/dashboard", persona=FakePersona())
    assert captured["cookie"] == "sid=abc123"
    assert captured["x-custom"] == "yes"


async def test_401_response_is_not_an_error_just_a_status(tmp_path):
    def handler(request):
        return httpx.Response(401, json={"error": "unauthorized"})

    engine = make_engine(tmp_path, handler=handler)
    resp = await engine.request("GET", "https://app.acme.test/admin")
    assert resp.status_code == 401
