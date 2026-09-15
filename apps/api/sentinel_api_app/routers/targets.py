"""Targets: creation, ownership verification, authorization acceptance,
scope rules (docs/02-scan-lifecycle.md Phase 0, docs/06-safety-legal-abuse.md
§1-2). Nothing downstream (personas, scans) is reachable for a target until
``is_scannable`` is true — see sentinel_db.models.target.Target.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_db.enums import OwnershipVerificationMethod
from sentinel_db.models import Organization, ScopeRule, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_current_org, get_owned_target, get_session
from ..schemas.target import (
    AuthorizationAccept,
    OwnershipChallengeOut,
    OwnershipChallengeRequest,
    OwnershipVerifyResult,
    ScopeRuleCreate,
    ScopeRuleOut,
    TargetCreate,
    TargetOut,
)
from ..services.ownership import generate_verification_token, verify_ownership

router = APIRouter(tags=["targets"])

_INSTRUCTIONS = {
    OwnershipVerificationMethod.DNS_TXT: (
        "Create a TXT record at _sentinel-verify.{domain} with the exact value shown."
    ),
    OwnershipVerificationMethod.WELL_KNOWN_FILE: (
        "Serve a file at https://{domain}/.well-known/sentinel-verify.txt whose entire "
        "body is the exact value shown."
    ),
    OwnershipVerificationMethod.META_TAG: (
        'Add <meta name="sentinel-verify" content="TOKEN"> to the <head> of '
        "https://{domain}/, replacing TOKEN with the exact value shown."
    ),
}


@router.post("/targets", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> Target:
    target = Target(
        organization_id=org.id,
        root_domain=payload.root_domain,
        display_name=payload.display_name,
        is_production=payload.is_production,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


@router.get("/targets", response_model=list[TargetOut])
async def list_targets(
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> list[Target]:
    result = await session.execute(select(Target).where(Target.organization_id == org.id))
    return list(result.scalars().all())


@router.get("/targets/{target_id}", response_model=TargetOut)
async def get_target(target: Target = Depends(get_owned_target)) -> Target:
    return target


@router.post("/targets/{target_id}/ownership-challenge", response_model=OwnershipChallengeOut)
async def create_ownership_challenge(
    payload: OwnershipChallengeRequest,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> OwnershipChallengeOut:
    token = generate_verification_token()
    target.ownership_verification_method = payload.method
    target.ownership_verification_token = token
    target.ownership_verified = False
    target.ownership_verified_at = None
    await session.commit()

    return OwnershipChallengeOut(
        method=payload.method,
        token=token,
        instructions=_INSTRUCTIONS[payload.method].format(domain=target.root_domain),
    )


@router.post("/targets/{target_id}/ownership-verify", response_model=OwnershipVerifyResult)
async def run_ownership_verification(
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> OwnershipVerifyResult:
    if not target.ownership_verification_method or not target.ownership_verification_token:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "No ownership challenge has been issued for this target yet — "
            "call POST /targets/{id}/ownership-challenge first.",
        )

    result = await verify_ownership(
        target.ownership_verification_method,
        target.root_domain,
        target.ownership_verification_token,
    )

    target.ownership_verified = result.verified
    target.ownership_verified_at = datetime.now(UTC) if result.verified else None
    await session.commit()

    return OwnershipVerifyResult(verified=result.verified, detail=result.detail)


@router.post("/targets/{target_id}/authorization", response_model=TargetOut)
async def accept_authorization(
    payload: AuthorizationAccept,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> Target:
    if not payload.accepted:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Authorization must be explicitly accepted."
        )

    target.authorization_accepted = True
    target.authorization_accepted_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(target)
    return target


@router.post(
    "/targets/{target_id}/scope-rules",
    response_model=ScopeRuleOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_scope_rule(
    payload: ScopeRuleCreate,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> ScopeRule:
    rule = ScopeRule(target_id=target.id, **payload.model_dump())
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return rule


@router.get("/targets/{target_id}/scope-rules", response_model=list[ScopeRuleOut])
async def list_scope_rules(
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> list[ScopeRule]:
    result = await session.execute(select(ScopeRule).where(ScopeRule.target_id == target.id))
    return list(result.scalars().all())
