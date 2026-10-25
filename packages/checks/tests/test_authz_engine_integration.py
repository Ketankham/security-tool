"""End-to-end: the authorization engine replaying real requests through the
real HttpEngine against a live multi-tenant fixture (docs/03 §4, docs/05 M2
exit criterion — find every planted bug, flag zero known-good endpoints).

This is the moat proven in miniature: a planted BOLA/IDOR leak is caught and
CONFIRMED via its canary, while the secure and public endpoints beside it
produce nothing.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from fakeredis.aioredis import FakeRedis
from sentinel_checks.authz import (
    AuthorizationEngine,
    AuthzBoundary,
    Confidence,
    ObservedRequest,
    PersonaProfile,
)
from sentinel_checks.authz.models import OracleLayer
from sentinel_core.http_engine import HttpEngine
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder

# Load the fixture module by path to read its canary/session maps (same
# collision-avoidance reason as conftest).
_fix = importlib.util.spec_from_file_location(
    "sentinel_checks_test_fixture_authz_app_consts",
    Path(__file__).parent / "fixtures" / "authz_app.py",
)
_mod = importlib.util.module_from_spec(_fix)  # type: ignore[arg-type]
_fix.loader.exec_module(_mod)  # type: ignore[union-attr]
CANARY: dict[str, str] = _mod.CANARY
TOKEN_FOR = {persona: tok for tok, (persona, _t, _r) in _mod.SESSIONS.items()}


class CookieTokenSession:
    """Minimal SessionState: carries one persona's auth cookie. Stands in for
    the Playwright storage_state PersonaSession wraps in production — the
    engine only needs cookies()/extra_headers()."""

    def __init__(self, persona_id: str, token: str) -> None:
        self.persona_id = persona_id
        self._token = token

    def cookies(self) -> dict[str, str]:
        return {"session": self._token}

    def extra_headers(self) -> dict[str, str]:
        return {}


def _personas() -> list[PersonaProfile]:
    return [
        PersonaProfile.anonymous(),
        PersonaProfile(
            "admin-a",
            "Admin A",
            "admin",
            trust_rank=30,
            tenant_key="A",
            canary_tokens=(CANARY["admin-a"],),
        ),
        PersonaProfile(
            "member-a",
            "Member A",
            "member",
            trust_rank=10,
            tenant_key="A",
            canary_tokens=(CANARY["member-a"],),
        ),
        PersonaProfile(
            "admin-b",
            "Admin B",
            "admin",
            trust_rank=30,
            tenant_key="B",
            canary_tokens=(CANARY["admin-b"],),
        ),
        PersonaProfile(
            "member-b",
            "Member B",
            "member",
            trust_rank=10,
            tenant_key="B",
            canary_tokens=(CANARY["member-b"],),
        ),
    ]


def _sessions() -> dict[str, CookieTokenSession]:
    return {p: CookieTokenSession(p, tok) for p, tok in TOKEN_FOR.items()}


def _build_engine(base_url: str, tmp_path) -> tuple[HttpEngine, AuthorizationEngine]:
    scope_guard = ScopeGuard(allowed_hosts={"127.0.0.1"}, target_ownership_verified=True)
    http = HttpEngine(
        scope_guard=scope_guard,
        rate_limiter=RateLimiter(FakeRedis()),
        recorder=TranscriptRecorder(LocalTranscriptStore(tmp_path / "transcripts")),
        target_id="t-1",
        scan_id="s-1",
    )
    authz = AuthorizationEngine(http=http, sessions=_sessions())
    return http, authz


async def test_planted_leak_is_caught_and_confirmed_secure_endpoints_are_silent(
    authz_server, tmp_path
):
    base = authz_server
    http, authz = _build_engine(base, tmp_path)
    try:
        # What admin-a's own crawl reached: its own secure profile, its own
        # leaky profile, and the public health endpoint.
        observed = [
            ObservedRequest("admin-a", "GET", f"{base}/api/profile/admin-a", "/api/profile/{id}"),
            ObservedRequest(
                "admin-a", "GET", f"{base}/api/leaky/profile/admin-a", "/api/leaky/profile/{id}"
            ),
            ObservedRequest("admin-a", "GET", f"{base}/api/health", "/api/health"),
        ]
        findings = await authz.run(observed=observed, personas=_personas())
    finally:
        await http.aclose()

    # Every finding is on the leaky endpoint — nothing from secure or health.
    assert findings, "expected the planted leak to be found"
    assert all("/api/leaky/profile/" in f.url for f in findings)

    # The deny-set for admin-a is {anon, member-a, admin-b, member-b}; the
    # leaky profile exposes admin-a's canary to every one of them.
    by_subject = {f.subject_persona_id: f for f in findings}
    assert set(by_subject) == {"anonymous", "member-a", "admin-b", "member-b"}

    # All confirmed, all via the deterministic canary layer, all carrying
    # admin-a's actual canary.
    for f in findings:
        assert f.confidence is Confidence.CONFIRMED
        assert f.oracle.layer is OracleLayer.CANARY
        assert f.oracle.canary_hit == CANARY["admin-a"]
        assert f.verification["passed"] is True
        assert f.verification["reproduced_count"] == 2
        assert len(f.evidence) == 2

    # Correct boundary classification.
    assert by_subject["anonymous"].boundary is AuthzBoundary.ANONYMOUS
    assert by_subject["member-a"].boundary is AuthzBoundary.VERTICAL
    assert by_subject["admin-b"].boundary is AuthzBoundary.HORIZONTAL
    assert by_subject["member-b"].boundary is AuthzBoundary.HORIZONTAL


async def test_secure_surface_alone_yields_zero_findings(authz_server, tmp_path):
    base = authz_server
    http, authz = _build_engine(base, tmp_path)
    try:
        observed = [
            ObservedRequest("admin-a", "GET", f"{base}/api/profile/admin-a", "/api/profile/{id}"),
            ObservedRequest("admin-a", "GET", f"{base}/api/health", "/api/health"),
        ]
        findings = await authz.run(observed=observed, personas=_personas())
    finally:
        await http.aclose()

    assert findings == []


async def test_write_methods_are_not_replayed_by_default(authz_server, tmp_path):
    # Read-only default: a DELETE in the observed set is never replayed.
    base = authz_server
    http, authz = _build_engine(base, tmp_path)
    try:
        observed = [
            ObservedRequest(
                "admin-a", "DELETE", f"{base}/api/leaky/profile/admin-a", "/api/leaky/profile/{id}"
            ),
        ]
        findings = await authz.run(observed=observed, personas=_personas())
    finally:
        await http.aclose()

    assert findings == []
