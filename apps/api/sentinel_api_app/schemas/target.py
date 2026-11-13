from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sentinel_db.enums import OwnershipVerificationMethod

from ..services.domains import normalize_root_domain


class TargetCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    # Accepts "https://app.example.com/login" and stores "app.example.com";
    # rejects ports, IPs, single-label names. See services/domains.py.
    root_domain: str = Field(min_length=1, max_length=2048)
    display_name: str = Field(min_length=1, max_length=200)
    is_production: bool = True

    @field_validator("root_domain")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return normalize_root_domain(v)


class TargetUpdate(BaseModel):
    """Rename a target or point it at another domain (QA #37: a target saved
    as abhyaasika.com whose app lives on www.abhyaasika.com)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    root_domain: str | None = Field(default=None, min_length=1, max_length=2048)
    display_name: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("root_domain")
    @classmethod
    def _normalize(cls, v: str | None) -> str | None:
        return normalize_root_domain(v) if v is not None else None


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    root_domain: str
    display_name: str
    is_production: bool
    ownership_verified: bool
    ownership_verification_method: OwnershipVerificationMethod | None
    ownership_verified_at: datetime | None
    authorization_accepted: bool
    # Effective for this deployment: true when the ownership gate is off
    # (see routers/targets.target_out), not just the stored verification.
    is_scannable: bool
    ownership_check_required: bool = True


class OwnershipChallengeOut(BaseModel):
    method: OwnershipVerificationMethod
    token: str
    instructions: str


class OwnershipChallengeRequest(BaseModel):
    method: OwnershipVerificationMethod


class OwnershipVerifyResult(BaseModel):
    verified: bool
    detail: str


_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}


class ScopeRuleCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    kind: str = Field(pattern=r"^(host|path_prefix|path_regex|method)$")
    pattern: str = Field(min_length=1, max_length=500)
    effect: str = Field(pattern=r"^(include|exclude)$")
    label: str = ""

    @model_validator(mode="after")
    def _pattern_fits_kind(self) -> ScopeRuleCreate:
        """Reject what the scope guard can't evaluate (QA #11: an invalid
        regex like "([" used to be saved and would only fail mid-scan)."""
        if self.kind == "path_regex":
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid regular expression: {exc}") from exc
        elif self.kind == "path_prefix":
            if not self.pattern.startswith("/"):
                raise ValueError("a path prefix must start with '/', e.g. /api/")
        elif self.kind == "method":
            self.pattern = self.pattern.upper()
            if self.pattern not in _HTTP_METHODS:
                raise ValueError(
                    f"unknown HTTP method; use one of {', '.join(sorted(_HTTP_METHODS))}"
                )
        elif self.kind == "host":
            host = self.pattern.lower()
            bare = host[2:] if host.startswith("*.") else host
            try:
                normalize_root_domain(bare)
            except ValueError as exc:
                raise ValueError(f"invalid host pattern: {exc}") from exc
            self.pattern = host
        return self


class ScopeRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: str
    pattern: str
    effect: str
    label: str


class AuthorizationAccept(BaseModel):
    accepted: bool = Field(
        description="Must be true — confirms the customer owns or is "
        "contractually authorized to test this target."
    )
