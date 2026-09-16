"""Proves the whole Phase-6-steps-1-3 pipeline against a small simulated
multi-tenant app: a planted horizontal IDOR (any logged-in user can read any
user's notes) gets caught via the canary layer, and a properly-protected
admin endpoint produces zero findings across every boundary tested against
it — the project's north-star anti-false-positive claim, exercised as a
real assertion rather than a slogan.

Uses httpx.MockTransport + a real HttpEngine, the same pattern
packages/core/tests/test_http_engine.py uses — this package reasons about
HTTP request/response shapes, not browser rendering, so a real server
(as packages/crawler and packages/auth need for real Playwright behaviour)
would be overkill here.
"""

from __future__ import annotations

import httpx
from fakeredis.aioredis import FakeRedis
from sentinel_checks.access_control import (
    ObservedRequest,
    OracleVerdict,
    PersonaIdentity,
    run_access_control,
)
from sentinel_core.http_engine import HttpEngine
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder

BASE = "https://app.acme.test"

NOTES = {"note-a1": "canary-aaa111", "note-b1": "canary-bbb222"}

ADMIN = PersonaIdentity(persona_id="admin", trust_rank=2, tenant_key="acme")
MEMBER_A = PersonaIdentity(
    persona_id="member-a", trust_rank=1, tenant_key="acme", canary_tokens=("canary-aaa111",)
)
MEMBER_B = PersonaIdentity(
    persona_id="member-b", trust_rank=1, tenant_key="beta", canary_tokens=("canary-bbb222",)
)


def _sid_from_cookie(request: httpx.Request) -> str | None:
    cookie = request.headers.get("cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("sid="):
            return part.removeprefix("sid=")
    return None


def _app_handler(request: httpx.Request) -> httpx.Response:
    sid = _sid_from_cookie(request)
    path = request.url.path

    if path.startswith("/notes/"):
        # The planted bug: no ownership check at all — any logged-in
        # persona can read any note by ID.
        if sid is None:
            return httpx.Response(401, json={"error": "unauthorized"})
        note_id = path.rsplit("/", 1)[-1]
        content = NOTES.get(note_id)
        if content is None:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json={"note": content})

    if path == "/admin/dashboard":
        # Properly protected: only the admin session is honoured.
        if sid != "admin":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(
            200, json={"page": "admin dashboard", "widgets": ["users", "billing"]}
        )

    return httpx.Response(404, json={"error": "not found"})


class _FakeSession:
    def __init__(self, persona_id: str) -> None:
        self.persona_id = persona_id

    def cookies(self) -> dict[str, str]:
        return {"sid": self.persona_id}

    def extra_headers(self) -> dict[str, str]:
        return {}


def _make_engine(tmp_path) -> HttpEngine:
    transport = httpx.MockTransport(_app_handler)
    client = httpx.AsyncClient(transport=transport, follow_redirects=False)
    scope_guard = ScopeGuard(allowed_hosts={"app.acme.test"}, target_ownership_verified=True)
    rate_limiter = RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000)
    recorder = TranscriptRecorder(LocalTranscriptStore(tmp_path))
    return HttpEngine(
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        recorder=recorder,
        target_id="target-1",
        scan_id="scan-1",
        client=client,
    )


async def test_horizontal_idor_confirmed_by_canary_in_both_directions(tmp_path):
    engine = _make_engine(tmp_path)
    observed = [
        ObservedRequest("GET", f"{BASE}/notes/note-a1", "/notes/{id}", "member-a"),
        ObservedRequest("GET", f"{BASE}/notes/note-b1", "/notes/{id}", "member-b"),
    ]
    result = await run_access_control(
        http_engine=engine,
        observed_requests=observed,
        personas=[MEMBER_A, MEMBER_B],
        session_for=lambda pid: _FakeSession(pid),
    )

    assert result.ambiguous_count == 0
    by_pair = {(c.requesting_persona_id, c.denied_persona_id): c for c in result.candidates}
    assert len(result.candidates) == 2

    a_leaked_to_b = by_pair[("member-a", "member-b")]
    assert a_leaked_to_b.verdict == OracleVerdict.CONFIRMED_BY_CANARY
    assert a_leaked_to_b.boundary == "horizontal"
    assert a_leaked_to_b.rule_id == "authz.horizontal"

    b_leaked_to_a = by_pair[("member-b", "member-a")]
    assert b_leaked_to_a.verdict == OracleVerdict.CONFIRMED_BY_CANARY
    assert b_leaked_to_a.boundary == "horizontal"


async def test_properly_protected_admin_endpoint_produces_zero_findings(tmp_path):
    """The anti-false-positive proof point: replaying admin's own request as
    every lower/other-tenant/anonymous identity must produce nothing, even
    though all three boundaries (vertical, horizontal, anonymous) apply to
    this exact request."""
    engine = _make_engine(tmp_path)
    observed = [ObservedRequest("GET", f"{BASE}/admin/dashboard", "/admin/dashboard", "admin")]

    result = await run_access_control(
        http_engine=engine,
        observed_requests=observed,
        personas=[ADMIN, MEMBER_A, MEMBER_B],
        session_for=lambda pid: _FakeSession(pid),
    )

    assert result.candidates == []
    assert result.ambiguous_count == 0


async def test_anonymous_cannot_reach_notes_endpoint_at_all(tmp_path):
    """The notes endpoint's IDOR bug is real, but it does at least require
    *some* session — the anonymous boundary should clear (401), not flag."""
    engine = _make_engine(tmp_path)
    observed = [ObservedRequest("GET", f"{BASE}/notes/note-a1", "/notes/{id}", "member-a")]

    result = await run_access_control(
        http_engine=engine,
        observed_requests=observed,
        personas=[MEMBER_A],
        session_for=lambda pid: _FakeSession(pid),
    )

    assert result.candidates == []
