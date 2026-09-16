from __future__ import annotations

import pytest
from sentinel_ai.factory import make_llm_client


def test_missing_api_key_raises_a_clear_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        make_llm_client(token_budget_limit=1000)


def test_explicit_api_key_bypasses_env_lookup():
    client = make_llm_client(token_budget_limit=1000, api_key="sk-test-not-real")
    assert client.budget.limit == 1000
