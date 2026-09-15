from __future__ import annotations

from sentinel_ai.budget import DEGRADE_THRESHOLD, TokenBudget
from sentinel_ai.models import TokenUsage


def test_remaining_and_fraction_used():
    budget = TokenBudget(limit=1000)
    budget.record(TokenUsage(input_tokens=100, output_tokens=100))
    assert budget.used == 200
    assert budget.remaining() == 800
    assert budget.fraction_used() == 0.2


def test_is_exhausted_at_or_over_limit():
    budget = TokenBudget(limit=100, used=100)
    assert budget.is_exhausted()
    budget2 = TokenBudget(limit=100, used=99)
    assert not budget2.is_exhausted()


def test_is_under_pressure_at_threshold():
    just_under = TokenBudget(limit=100, used=int(DEGRADE_THRESHOLD * 100) - 1)
    at_threshold = TokenBudget(limit=100, used=int(DEGRADE_THRESHOLD * 100))
    assert not just_under.is_under_pressure()
    assert at_threshold.is_under_pressure()


def test_zero_limit_is_always_exhausted_and_under_pressure():
    budget = TokenBudget(limit=0)
    assert budget.is_exhausted()
    assert budget.is_under_pressure()
    assert budget.fraction_used() == 1.0
