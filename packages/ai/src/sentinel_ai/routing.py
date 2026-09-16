"""Model routing table (ADR-0001, docs/01-architecture.md §3.4).

    Opus 5    — permission-model hypothesis, business-logic planning,
                ambiguous-diff adjudication (low volume, high value)
    Sonnet 5  — login-flow synthesis, endpoint/parameter classification,
                report narrative
    Haiku 4.5 — bulk triage, dedup pre-filter, response summarisation
                (high volume, cheap)

Overridable via settings for a provider/model-name change without touching
call sites — see docs/01 §3.4 ("abstracted behind our own LLMClient so a
second provider is a config change, not a refactor").
"""

from __future__ import annotations

from .models import ModelTier

DEFAULT_MODEL_IDS: dict[ModelTier, str] = {
    "high": "claude-opus-5",
    "mid": "claude-sonnet-5",
    "low": "claude-haiku-4-5-20251001",
}

# Under budget pressure, LLMClient steps a requested tier down this ladder
# rather than refusing outright — "low" has nowhere cheaper to go.
DEGRADE_TIER: dict[ModelTier, ModelTier] = {
    "high": "mid",
    "mid": "low",
    "low": "low",
}
