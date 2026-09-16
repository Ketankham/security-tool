"""LLMClient tested entirely against a fake MessagesAPI — no real Anthropic
call, no API key needed. This is deliberate (ADR-0001): the client's
correctness (structured-only output, budget enforcement, degradation) is
provider-independent and must never depend on live network access."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest
from sentinel_ai.budget import BudgetExhaustedError, TokenBudget
from sentinel_ai.client import LLMClient
from sentinel_ai.routing import DEFAULT_MODEL_IDS


def _tool_use_response(*, tool_input: dict, input_tokens: int = 100, output_tokens: int = 50):
    block = SimpleNamespace(type="tool_use", name="emit_result", input=tool_input)
    return SimpleNamespace(
        content=[block],
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
    )


@dataclass
class FakeMessagesAPI:
    """Records every call it receives and returns queued canned responses —
    the fake stands in for anthropic.AsyncAnthropic(...).messages."""

    responses: list = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


async def test_complete_structured_returns_tool_input_as_data():
    api = FakeMessagesAPI(responses=[_tool_use_response(tool_input={"label": "object_reference"})])
    client = LLMClient(api, budget=TokenBudget(limit=100_000))

    result = await client.complete_structured(
        tier="mid", system="classify", prompt="param: id", schema={"type": "object"}
    )

    assert result.data == {"label": "object_reference"}
    assert result.model_used == DEFAULT_MODEL_IDS["mid"]
    assert not result.degraded


async def test_complete_structured_forces_tool_choice_and_schema():
    api = FakeMessagesAPI(responses=[_tool_use_response(tool_input={})])
    client = LLMClient(api, budget=TokenBudget(limit=100_000))

    schema = {"type": "object", "properties": {"label": {"type": "string"}}}
    await client.complete_structured(tier="low", system="s", prompt="p", schema=schema)

    call = api.calls[0]
    assert call["tool_choice"] == {"type": "tool", "name": "emit_result"}
    assert call["tools"][0]["input_schema"] == schema
    assert call["model"] == DEFAULT_MODEL_IDS["low"]


async def test_budget_records_usage_from_response():
    api = FakeMessagesAPI(
        responses=[_tool_use_response(tool_input={}, input_tokens=200, output_tokens=80)]
    )
    budget = TokenBudget(limit=100_000)
    client = LLMClient(api, budget=budget)

    await client.complete_structured(tier="high", system="s", prompt="p", schema={})

    assert budget.used == 280


async def test_exhausted_budget_raises_before_any_call():
    api = FakeMessagesAPI(responses=[])
    budget = TokenBudget(limit=100, used=100)
    client = LLMClient(api, budget=budget)

    with pytest.raises(BudgetExhaustedError):
        await client.complete_structured(tier="high", system="s", prompt="p", schema={})

    assert api.calls == []  # never even attempted the call


async def test_budget_under_pressure_degrades_to_cheaper_tier():
    api = FakeMessagesAPI(responses=[_tool_use_response(tool_input={})])
    budget = TokenBudget(limit=100, used=85)  # 85% used, over the 80% threshold
    client = LLMClient(api, budget=budget)

    result = await client.complete_structured(tier="high", system="s", prompt="p", schema={})

    assert result.requested_tier == "high"
    assert result.effective_tier == "mid"
    assert result.degraded
    assert result.model_used == DEFAULT_MODEL_IDS["mid"]


async def test_low_tier_has_nowhere_cheaper_to_degrade_to():
    api = FakeMessagesAPI(responses=[_tool_use_response(tool_input={})])
    budget = TokenBudget(limit=100, used=95)
    client = LLMClient(api, budget=budget)

    result = await client.complete_structured(tier="low", system="s", prompt="p", schema={})

    assert result.effective_tier == "low"
    assert not result.degraded


async def test_missing_tool_use_block_raises_rather_than_parsing_prose():
    text_only_response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="I refuse to use tools today")],
        usage=SimpleNamespace(input_tokens=10, output_tokens=10),
    )
    api = FakeMessagesAPI(responses=[text_only_response])
    client = LLMClient(api, budget=TokenBudget(limit=100_000))

    with pytest.raises(ValueError, match="tool_use"):
        await client.complete_structured(tier="low", system="s", prompt="p", schema={})
