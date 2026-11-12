from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sentinel_db.enums import CredentialKind, LoginStrategy


class CredentialCreate(BaseModel):
    """The plaintext secret is accepted here and immediately encrypted —
    it is never stored or logged in this form (docs/01 §6.3)."""

    kind: CredentialKind
    secret: str = Field(min_length=1, repr=False)


# Which fields each login-step action needs. The replayer
# (sentinel_auth.replay) asserts these at scan time; checking them here turns
# a hand-written bad recipe into a 422 at save time instead of a failed login
# mid-scan.
_STEP_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "goto": ("value",),
    "fill": ("selector", "value"),
    "fill_secret": ("selector", "credential_ref"),
    "click": ("selector",),
    "wait_for_selector": ("selector",),
    "wait_for_url": ("value",),
}


class LoginStepIn(BaseModel):
    """Mirrors sentinel_auth.models.LoginStep's shape (docs/01 §6.4) — kept
    as a separate Pydantic schema rather than importing that dataclass so
    the API never depends on sentinel-auth (and, transitively, Playwright).
    The worker reconstructs the dataclass from this JSON at replay time."""

    action: Literal["goto", "fill", "fill_secret", "click", "wait_for_selector", "wait_for_url"]
    selector: str | None = None
    value: str | None = None
    credential_ref: str | None = None
    timeout_s: float = Field(default=10.0, gt=0)

    @model_validator(mode="after")
    def _fields_for_action(self) -> LoginStepIn:
        missing = [f for f in _STEP_REQUIRED_FIELDS[self.action] if not getattr(self, f)]
        if missing:
            raise ValueError(f"step '{self.action}' needs: {', '.join(missing)}")
        if self.action == "fill" and self.credential_ref:
            raise ValueError("use 'fill_secret' (not 'fill') for steps that type a credential")
        return self


class SuccessAssertionIn(BaseModel):
    kind: Literal["url_contains", "selector_visible", "selector_hidden"]
    value: str = Field(min_length=1)
    timeout_s: float = Field(default=10.0, gt=0)


class LoginRecipeIn(BaseModel):
    start_url: str = Field(min_length=1)
    steps: list[LoginStepIn] = Field(min_length=1)
    success_assertion: SuccessAssertionIn
    strategy: Literal["form"] = "form"
    max_duration_s: float = Field(default=30.0, gt=0)
    # Explicit confirmation that the login page legitimately lives on a
    # host outside the target's domain (SSO). Without it, the API and the
    # worker refuse any navigation off the target (sentinel_core.login_safety).
    allow_off_domain: bool = False

    @model_validator(mode="after")
    def _one_secret(self) -> LoginRecipeIn:
        """The worker attaches the persona's single stored credential to the
        recipe's fill_secret step (worker auth_adapter.establish_persona), so
        a recipe needs exactly one credential_ref to bind it to."""
        refs = {s.credential_ref for s in self.steps if s.action == "fill_secret"}
        if not refs:
            raise ValueError("login recipe needs a 'fill_secret' step for the password")
        if len(refs) > 1:
            raise ValueError("all 'fill_secret' steps must use the same credential_ref")
        return self


class PersonaCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    label: str = Field(min_length=1, max_length=200)
    role_name: str = Field(min_length=1, max_length=100)
    # Bounded (QA #14: 99999999999999999999 overflowed the INTEGER column
    # and returned a 500). Ranks only need to order roles, e.g. 0 anonymous,
    # 10 member, 50 admin.
    trust_rank: int = Field(ge=0, le=1000, default=0)
    tenant_key: str | None = Field(default=None, max_length=200)
    login_strategy: LoginStrategy | None = None
    credential: CredentialCreate | None = None
    login_recipe: LoginRecipeIn | None = None
    expected_denied: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _recipe_needs_password(self) -> PersonaCreate:
        if self.login_recipe is not None and self.credential is None:
            raise ValueError(
                "a login recipe needs a password (credential) to fill its 'fill_secret' step"
            )
        return self


class PersonaLoginUpdate(BaseModel):
    """Set or replace an existing persona's login. Personas can't be deleted
    (transcripts reference them), so this is how a persona created without a
    recipe — or with a wrong one, or a changed password — gets fixed."""

    login_recipe: LoginRecipeIn | None = None
    credential: CredentialCreate | None = None

    @model_validator(mode="after")
    def _something_to_change(self) -> PersonaLoginUpdate:
        if self.login_recipe is None and self.credential is None:
            raise ValueError("provide login_recipe and/or credential")
        return self


class PersonaLoginOut(BaseModel):
    """The saved recipe, for prefilling "Edit login" (QA #24). Never holds
    the password: recipes only reference it by credential_ref, and this
    response says whether one is stored, not what it is."""

    login_recipe: dict | None
    has_password: bool


class PersonaOut(BaseModel):
    """Never includes credential ciphertext or session_state — those never
    leave the worker's memory except encrypted-at-rest (docs/01 §6.3)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    label: str
    role_name: str
    trust_rank: int
    tenant_key: str | None
    login_strategy: LoginStrategy | None
    is_available: bool
    unavailable_reason: str | None
    expected_denied: list[str]
    has_login_recipe: bool = Field(validation_alias="login_recipe")

    @field_validator("has_login_recipe", mode="before")
    @classmethod
    def _presence_only(cls, v: object) -> bool:
        """The ORM attribute is the recipe dict itself (or None) — this
        response never echoes it back (it's not secret, but callers have no
        use for it and it's simpler to keep this response small)."""
        return v is not None
