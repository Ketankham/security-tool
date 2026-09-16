"""Org creation. In production this happens behind Clerk's org-creation
flow; exposed directly here so the platform is testable end-to-end without
Clerk wired up yet (docs/05-v1-roadmap.md M0/M1 boundary)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_db import get_session
from sentinel_db.models import Organization
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_crypto, get_current_org
from ..schemas.organization import OrganizationCreate, OrganizationOut

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post("", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    session: AsyncSession = Depends(get_session),
    crypto: EnvelopeCrypto = Depends(get_crypto),
) -> Organization:
    slug_query = select(Organization).where(Organization.slug == payload.slug)
    existing = await session.execute(slug_query)
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An organization with this slug already exists."
        )

    data_key = crypto.generate_data_key()
    org = Organization(
        name=payload.name,
        slug=payload.slug,
        wrapped_data_key=crypto.wrap_data_key(data_key),
    )
    session.add(org)
    await session.commit()
    await session.refresh(org)
    return org


@router.get("/me", response_model=OrganizationOut)
async def get_my_organization(org: Organization = Depends(get_current_org)) -> Organization:
    return org
