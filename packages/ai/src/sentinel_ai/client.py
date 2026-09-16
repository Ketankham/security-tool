"""LLMClient: the single seam between every AI-assisted phase and the
model provider (ADR-0001). Two structural rules live here, not just in
prose:

1. **Structured output only.** Every call forces tool-use with a caller-
   supplied JSON schema; nothing ever parses free-text prose out of a
   response (docs/01 §3.4). A model that can't produce valid structured
   output for the schema is a call that fails loudly, not one whose
   half-parsed guess quietly becomes a "finding".
2. **The budget is enforced here, not trusted to callers.** Exhausted →
   raise (docs/01 §3.4's "disables optional AI stages" starts at the call
   site catching BudgetExhaustedError). Under pressure → transparently
   degrade to a cheaper model tier and say so in the result.

The `MessagesAPI` protocol is the real seam: tests inject a fake,
production wires in `anthropic.AsyncAnthropic(...).messages`. Nothing here
imports the concrete Anthropic client class directly.
"""

from __future__ import annotations

from typing import Any, Protocol

from .budget import BudgetExhaustedError, TokenBudget
from .models import ModelTier, StructuredCallResult, TokenUsage
from .routing import DEFAULT_MODEL_IDS, DEGRADE_TIER

_RESULT_TOOL_NAME = "emit_result"


class MessagesAPI(Protocol):
    async def create(self, **kwargs: Any) -> Any: ...


class LLMClient:
    def __init__(
        self,
        api: MessagesAPI,
        *,
        budget: TokenBudget,
        model_ids: dict[ModelTier, str] | None = None,
    ) -> None:
        self._api = api
        self._budget = budget
        self._model_ids = model_ids or DEFAULT_MODEL_IDS

    @property
    def budget(self) -> TokenBudget:
        return self._budget

    async def complete_structured(
        self,
        *,
        tier: ModelTier,
        system: str,
        prompt: str,
        schema: dict,
        max_tokens: int = 1024,
    ) -> StructuredCallResult:
        if self._budget.is_exhausted():
            raise BudgetExhaustedError(self._budget)

        effective_tier = tier
        if self._budget.is_under_pressure():
            effective_tier = DEGRADE_TIER[tier]

        model = self._model_ids[effective_tier]

        response = await self._api.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            tools=[
                {
                    "name": _RESULT_TOOL_NAME,
                    "description": "Emit the structured result for this request.",
                    "input_schema": schema,
                }
            ],
            tool_choice={"type": "tool", "name": _RESULT_TOOL_NAME},
        )

        usage = TokenUsage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )
        self._budget.record(usage)

        data = _extract_tool_input(response, _RESULT_TOOL_NAME)

        return StructuredCallResult(
            data=data,
            usage=usage,
            model_used=model,
            requested_tier=tier,
            effective_tier=effective_tier,
        )


def _extract_tool_input(response: Any, tool_name: str) -> dict:
    for block in response.content:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == tool_name:
            return dict(block.input)
    raise ValueError(
        f"Model response contained no '{tool_name}' tool_use block — "
        "forced tool_choice should make this impossible; treat as a "
        "provider-side error, not a parseable-prose fallback (ADR-0001)."
    )
