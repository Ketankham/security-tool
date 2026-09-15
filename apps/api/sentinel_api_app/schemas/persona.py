from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sentinel_db.enums import CredentialKind, LoginStrategy


class CredentialCreate(BaseModel):
    """The plaintext secret is accepted here and immediately encrypted —
    it is never stored or logged in this form (docs/01 §6.3)."""

    kind: CredentialKind
    secret: str = Field(min_length=1, repr=False)


class PersonaCreate(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    role_name: str = Field(min_length=1, max_length=100)
    trust_rank: int = Field(ge=0, default=0)
    tenant_key: str | None = Field(default=None, max_length=200)
    login_strategy: LoginStrategy | None = None
    credential: CredentialCreate | None = None
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
