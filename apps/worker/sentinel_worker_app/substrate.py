"""Builds the shared-substrate objects (docs/01-architecture.md §4.1) from
persisted Target/ScopeRule rows for one scan run. Kept separate from
scan_runner.py so that module reads as phase orchestration, not wiring.
"""

from __future__ import annotations

from redis.asyncio import Redis
from sentinel_core.http_engine import HttpEngine
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.scope_guard import ScopeRule as CoreScopeRule
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder
from sentinel_db.models import ScopeRule, Target

from .config import Settings


def build_scope_guard(target: Target, scope_rules: list[ScopeRule]) -> ScopeGuard:
    allowed_hosts = {target.root_domain, f"*.{target.root_domain}"}
    rules = [
        CoreScopeRule(kind=r.kind, pattern=r.pattern, effect=r.effect, label=r.label)
        for r in scope_rules
    ]
    return ScopeGuard(
        allowed_hosts=allowed_hosts,
        rules=rules,
        target_ownership_verified=target.ownership_verified,
    )


def build_http_engine(
    *,
    scope_guard: ScopeGuard,
    redis_client: Redis,
    settings: Settings,
    target_id: str,
    scan_id: str,
) -> HttpEngine:
    rate_limiter = RateLimiter(redis_client)
    recorder = TranscriptRecorder(LocalTranscriptStore(settings.storage_local_path))
    return HttpEngine(
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        recorder=recorder,
        target_id=target_id,
        scan_id=scan_id,
    )
