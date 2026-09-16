"""LLMClient abstraction (ADR-0001): structured-output-only calls, model
routing (Opus/Sonnet/Haiku by tier), and per-scan token budget enforcement
with graceful degradation. The Anthropic SDK itself is imported only in
factory.py — everything else depends solely on the MessagesAPI protocol.
"""

from .budget import BudgetExhaustedError, TokenBudget
from .client import LLMClient, MessagesAPI
from .factory import make_llm_client
from .models import ModelTier, StructuredCallResult, TokenUsage
from .routing import DEFAULT_MODEL_IDS, DEGRADE_TIER

__all__ = [
    "LLMClient",
    "MessagesAPI",
    "make_llm_client",
    "TokenBudget",
    "BudgetExhaustedError",
    "ModelTier",
    "StructuredCallResult",
    "TokenUsage",
    "DEFAULT_MODEL_IDS",
    "DEGRADE_TIER",
]
