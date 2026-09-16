"""Production wiring: builds an LLMClient backed by the real Anthropic API.
Kept separate from client.py so that module never has to import the
concrete `anthropic` client class — tests exercise LLMClient entirely
through the MessagesAPI protocol with a fake.
"""

from __future__ import annotations

import os
from typing import cast

from .budget import TokenBudget
from .client import LLMClient, MessagesAPI


def make_llm_client(*, token_budget_limit: int, api_key: str | None = None) -> LLMClient:
    import anthropic  # noqa: PLC0415 — deferred so importing this package never requires the key to exist

    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not configured. AI-assisted phases cannot run without it — "
            "the scan should mark them skipped/degraded rather than fail outright (docs/01 §3.4)."
        )

    client = anthropic.AsyncAnthropic(api_key=key)
    # The real SDK's `.messages.create` is a richly-overloaded, keyword-only
    # method — structurally incompatible with our deliberately narrow
    # `**kwargs` MessagesAPI protocol even though every call this client
    # makes is a valid call. This is the one place that gap is bridged.
    messages_api = cast(MessagesAPI, client.messages)
    return LLMClient(messages_api, budget=TokenBudget(limit=token_budget_limit))
