"""Shared types for the LLM layer (ADR-0001)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Matches sentinel_ai.routing.DEFAULT_MODEL_IDS: "high" for low-volume,
# high-value decisions (permission-model hypothesis, business-logic
# planning), "mid" for login-flow synthesis and report narrative, "low" for
# bulk triage/dedup (docs/01-architecture.md §3.4).
ModelTier = Literal["high", "mid", "low"]


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class StructuredCallResult:
    data: dict
    usage: TokenUsage
    model_used: str
    requested_tier: ModelTier
    effective_tier: ModelTier

    @property
    def degraded(self) -> bool:
        """True if budget pressure forced a cheaper tier than requested
        (docs/01 §3.4: 'exceeding it degrades to a cheaper model')."""
        return self.effective_tier != self.requested_tier
