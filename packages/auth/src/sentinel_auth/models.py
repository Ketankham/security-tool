"""LoginRecipe: recorded once (AI-assisted, in production), replayed
deterministically forever after (docs/01-architecture.md §6.4).

Strategies: `form` (replay steps that type the password — the common case),
and, for sites a recipe can't drive (CAPTCHA, SSO, OTP), `cookie` and
`header`: the tester logs in by hand and pastes the session, and the replay
only checks that it still works (v1 #1). The API stores these as
LoginStrategy.FORM / MANUAL_SESSION / API_TOKEN respectively.
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


AssertionKind = Literal["url_contains", "url_not_contains", "selector_visible", "selector_hidden"]

# form: replay recorded steps that type the password. cookie / header: the
# tester logged in by hand and pasted the session (sentinel_core.session_import).
LoginStrategyName = Literal["form", "cookie", "header"]


@dataclass(frozen=True, slots=True)
class SuccessAssertion:
    # url_not_contains is the usual check for cookie/header logins and for
    # apps whose post-login URL varies: "the browser did not end up on
    # /sign-in".
    kind: AssertionKind
    value: str
    timeout_s: float = 10.0


@dataclass(frozen=True, slots=True)
class LoginRecipe:
    start_url: str
    steps: tuple[LoginStep, ...]
    success_assertion: SuccessAssertion
    strategy: LoginStrategyName = "form"
    version: int = 1
    max_duration_s: float = 30.0
    # strategy == "header": the request header the pasted value goes in.
    header_name: str | None = None


@dataclass(frozen=True, slots=True)
class LoginReplayResult:
    success: bool
    storage_state: dict | None = None
    error: str | None = None
    duration_s: float = 0.0
    # Where the browser ended up, and (when asked for) a JPEG of the page —
    # for the dashboard's Test login result. Never logged or persisted.
    final_url: str | None = None
    screenshot: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class Credential:
    """Plaintext secret material, resolved locally just before replay and
    never logged, never serialised, never handed to the state machine or
    the DB in this form (docs/01 §6.3)."""

    ref: str
    secret: str = field(repr=False)
