from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sentinel_db.enums import CredentialKind, LoginStrategy


class CredentialCreate(BaseModel):
    """The plaintext secret is accepted here and immediately encrypted —
    it is never stored or logged in this form (docs/01 §6.3)."""

    kind: CredentialKind
    secret: str = Field(min_length=1, repr=False)


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


class PersonaCreate(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    role_name: str = Field(min_length=1, max_length=100)
    trust_rank: int = Field(ge=0, default=0)
    tenant_key: str | None = Field(default=None, max_length=200)
    login_strategy: LoginStrategy | None = None
    credential: CredentialCreate | None = None
    login_recipe: LoginRecipeIn | None = None
    expected_denied: list[str] = Field(default_factory=list)


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
