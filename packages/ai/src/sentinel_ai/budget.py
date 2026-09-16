"""Per-scan token budget (docs/01-architecture.md §3.4, ADR-0001
"Consequences"): the hard cost-control mechanism. Enforced in the client,
not left to callers' discipline — a check module that forgets to watch its
own token spend is exactly how a huge app turns into a surprise bill.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import TokenUsage

# Above this fraction of the budget spent, LLMClient starts degrading
# requested tiers to a cheaper model rather than waiting until the budget
# is fully exhausted and refusing outright.
DEGRADE_THRESHOLD = 0.8


@dataclass(slots=True)
class TokenBudget:
    limit: int
    used: int = field(default=0)

    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def fraction_used(self) -> float:
        if self.limit <= 0:
            return 1.0
        return min(1.0, self.used / self.limit)

    def is_exhausted(self) -> bool:
        return self.used >= self.limit

    def is_under_pressure(self) -> bool:
        return self.fraction_used() >= DEGRADE_THRESHOLD

    def record(self, usage: TokenUsage) -> None:
        self.used += usage.total


class BudgetExhaustedError(RuntimeError):
    """Raised when a call is attempted with no budget left at all — not
    when merely under pressure (that degrades the model tier instead;
    see LLMClient.complete_structured)."""

    def __init__(self, budget: TokenBudget) -> None:
        self.budget = budget
        super().__init__(
            f"LLM token budget exhausted: {budget.used}/{budget.limit} used. "
            "This scan's remaining AI-assisted phases should be marked "
            "degraded/skipped rather than retried (docs/01 §3.4)."
        )
