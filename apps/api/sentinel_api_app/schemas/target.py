from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sentinel_db.enums import OwnershipVerificationMethod


class TargetCreate(BaseModel):
    root_domain: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=200)
    is_production: bool = True


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
    is_scannable: bool


class OwnershipChallengeOut(BaseModel):
    method: OwnershipVerificationMethod
    token: str
    instructions: str


class OwnershipChallengeRequest(BaseModel):
    method: OwnershipVerificationMethod


class OwnershipVerifyResult(BaseModel):
    verified: bool
    detail: str


class ScopeRuleCreate(BaseModel):
    kind: str = Field(pattern=r"^(host|path_prefix|path_regex|method)$")
    pattern: str = Field(min_length=1, max_length=500)
    effect: str = Field(pattern=r"^(include|exclude)$")
    label: str = ""


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
