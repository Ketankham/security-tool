import pytest
from fakeredis.aioredis import FakeRedis
from sentinel_core.rate_limiter import RateLimiter


@pytest.fixture
async def redis():
    r = FakeRedis()
    yield r
    await r.aclose()


async def test_burst_allows_up_to_burst_then_blocks(redis):
    limiter = RateLimiter(redis, default_rate_per_sec=1.0, burst=3)
    results = [await limiter.try_acquire("target-1") for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]


async def test_different_targets_have_independent_buckets(redis):
    limiter = RateLimiter(redis, default_rate_per_sec=1.0, burst=1)
    a = await limiter.try_acquire("target-a")
    b = await limiter.try_acquire("target-b")
    assert a.allowed and b.allowed


async def test_backpressure_reduces_effective_rate(redis):
    limiter = RateLimiter(redis, default_rate_per_sec=10.0, burst=1, min_backpressure_factor=0.01)
    await limiter.try_acquire("target-1")  # drain the single burst token
    await limiter.report_backpressure("target-1", reason="429", factor=0.1)

    # Immediately after backpressure, effective rate is much lower, so the
    # wait time to refill one token should be much longer than 1/10s.
    result = await limiter.try_acquire("target-1")
    assert not result.allowed
    assert result.wait_seconds > 0.5


async def test_report_success_clears_backpressure_once_recovered(redis):
    limiter = RateLimiter(redis, default_rate_per_sec=10.0, burst=1)
    await limiter.report_backpressure("target-1", reason="429", factor=0.5)
    factor_before = await redis.get("ratelimit:factor:target-1")
    assert factor_before is not None

    # Recovery is gradual (x1.1 per success) — repeated successes eventually
    # clear the factor key entirely once it reaches >= 1.0.
    for _ in range(60):
        await limiter.report_success("target-1")
    factor_after = await redis.get("ratelimit:factor:target-1")
    assert factor_after is None
