"""LoginRecipe: recorded once (AI-assisted, in production), replayed
deterministically forever after (docs/01-architecture.md §6.4).

M1 scope is the `form` strategy only — the overwhelmingly common case and
enough to prove the whole persona pipeline end to end. oauth_redirect / saml
/ api_token / har_replay / manual_session are modelled in
sentinel_db.enums.LoginStrategy already; their replay executors are M2+
work (docs/05-v1-roadmap.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

StepAction = Literal["goto", "fill", "fill_secret", "click", "wait_for_selector", "wait_for_url"]


@dataclass(frozen=True, slots=True)
class LoginStep:
    action: StepAction
    selector: str | None = None
    value: str | None = None
    # For `fill_secret`: a name the caller resolves against locally-held
    # credentials at replay time. The recipe itself never contains a
    # plaintext secret — docs/01 §6.3 rule 3 (never in an LLM prompt, and
    # by the same logic, never persisted in this object either).
    credential_ref: str | None = None
    timeout_s: float = 10.0


@dataclass(frozen=True, slots=True)
class SuccessAssertion:
    kind: Literal["url_contains", "selector_visible", "selector_hidden"]
    value: str
    timeout_s: float = 10.0


@dataclass(frozen=True, slots=True)
class LoginRecipe:
    start_url: str
    steps: tuple[LoginStep, ...]
    success_assertion: SuccessAssertion
    strategy: Literal["form"] = "form"
    version: int = 1
    max_duration_s: float = 30.0


@dataclass(frozen=True, slots=True)
class LoginReplayResult:
    success: bool
    storage_state: dict | None = None
    error: str | None = None
    duration_s: float = 0.0


@dataclass(frozen=True, slots=True)
class Credential:
    """Plaintext secret material, resolved locally just before replay and
    never logged, never serialised, never handed to the state machine or
    the DB in this form (docs/01 §6.3)."""

    ref: str
    secret: str = field(repr=False)
