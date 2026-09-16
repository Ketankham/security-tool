"""Adaptive, per-target rate limiter (docs/01-architecture.md §4.1 item 3).

Shared across every phase/worker touching one target so five scan phases
running concurrently can't collectively exceed the customer's tolerance.
Backed by Redis so it's correct across multiple worker processes/hosts.

Algorithm: a token bucket, refilled continuously at ``base_rate_per_sec *
backpressure_factor`` tokens/sec, capped at ``burst``. The read-modify-write
is done with Redis WATCH/MULTI optimistic locking (retried on contention)
rather than a Lua script — this keeps the limiter portable to Redis-like
services that restrict EVAL/EVALSHA (some managed/proxied Redis do) and to
fakeredis in tests without extra native dependencies.

Backpressure: call ``report_backpressure()`` on a 429/503 or a WAF-block
signature and the effective rate for that target drops (exponential-ish,
via a multiplicative factor with a TTL) without needing a long-lived
in-process object — any worker, any process, sees the slowdown immediately.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import structlog
from redis.asyncio import Redis
from redis.asyncio.client import WatchError

log = structlog.get_logger(__name__)

_MAX_CAS_RETRIES = 10


@dataclass(frozen=True, slots=True)
class AcquireResult:
    allowed: bool
    wait_seconds: float


class RateLimiter:
    def __init__(
        self,
        redis: Redis,
        *,
        default_rate_per_sec: float = 5.0,
        burst: int = 10,
        min_backpressure_factor: float = 0.05,
    ) -> None:
        self._redis = redis
        self._default_rate = default_rate_per_sec
        self._burst = burst
        self._min_factor = min_backpressure_factor

    def _bucket_key(self, target_id: str) -> str:
        return f"ratelimit:bucket:{target_id}"

    def _factor_key(self, target_id: str) -> str:
        return f"ratelimit:factor:{target_id}"

    async def _effective_rate(self, target_id: str, base_rate: float | None) -> float:
        rate = base_rate if base_rate is not None else self._default_rate
        factor_raw = await self._redis.get(self._factor_key(target_id))
        factor = float(factor_raw) if factor_raw is not None else 1.0
        return max(rate * factor, rate * self._min_factor)

    async def try_acquire(
        self, target_id: str, *, cost: float = 1.0, base_rate: float | None = None
    ) -> AcquireResult:
        rate = await self._effective_rate(target_id, base_rate)
        burst = self._burst
        bucket_key = self._bucket_key(target_id)

        for _ in range(_MAX_CAS_RETRIES):
            async with self._redis.pipeline(transaction=True) as pipe:
                await pipe.watch(bucket_key)
                # redis-py's pipeline stubs type queued commands as a plain
                # return value rather than Awaitable under transaction=True,
                # even though awaiting them is correct at runtime.
                raw_tokens, raw_ts = await pipe.hmget(bucket_key, ["tokens", "ts"])  # type: ignore[misc]
                now = time.time()
                tokens = float(raw_tokens) if raw_tokens is not None else float(burst)
                ts = float(raw_ts) if raw_ts is not None else now

                elapsed = max(0.0, now - ts)
                tokens = min(float(burst), tokens + elapsed * rate)

                if tokens >= cost:
                    tokens -= cost
                    allowed, wait_time = True, 0.0
                else:
                    allowed, wait_time = False, (cost - tokens) / rate

                pipe.multi()
                pipe.hset(bucket_key, mapping={"tokens": tokens, "ts": now})
                pipe.expire(bucket_key, 3600)
                try:
                    await pipe.execute()
                except WatchError:
                    continue  # someone else updated the bucket concurrently — retry
                return AcquireResult(allowed=allowed, wait_seconds=wait_time)

        # Contention exhausted our retry budget (very high concurrency on one
        # target). Fail safe: deny rather than risk over-issuing tokens.
        return AcquireResult(allowed=False, wait_seconds=1.0 / rate)

    async def acquire(
        self,
        target_id: str,
        *,
        cost: float = 1.0,
        base_rate: float | None = None,
        _sleep=None,
    ) -> None:
        """Block (async sleep) until a token is available."""
        import asyncio

        sleep = _sleep or asyncio.sleep
        while True:
            result = await self.try_acquire(target_id, cost=cost, base_rate=base_rate)
            if result.allowed:
                return
            await sleep(min(result.wait_seconds, 5.0) + 0.01)

    async def report_backpressure(
        self, target_id: str, *, reason: str, factor: float = 0.5, ttl_s: int = 60
    ) -> None:
        """Multiplicatively cut the effective rate for this target. Repeated
        calls compound (each halves again, floored at min_backpressure_factor),
        which is the right shape for repeated 429s in a burst."""
        key = self._factor_key(target_id)
        current_raw = await self._redis.get(key)
        current = float(current_raw) if current_raw is not None else 1.0
        new_factor = max(current * factor, self._min_factor)
        await self._redis.set(key, new_factor, ex=ttl_s)
        log.warning(
            "rate_limiter.backpressure", target_id=target_id, reason=reason, new_factor=new_factor
        )

    async def report_success(self, target_id: str) -> None:
        """Let the rate recover gradually rather than snapping back to full
        speed, which would just trigger the next 429."""
        key = self._factor_key(target_id)
        current_raw = await self._redis.get(key)
        if current_raw is None:
            return
        current = float(current_raw)
        if current >= 1.0:
            await self._redis.delete(key)
            return
        recovered = min(1.0, current * 1.1)
        ttl = await self._redis.ttl(key)
        await self._redis.set(key, recovered, ex=ttl if ttl and ttl > 0 else 60)
