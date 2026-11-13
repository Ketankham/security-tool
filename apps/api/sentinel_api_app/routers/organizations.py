"""Org creation. In production this happens behind Clerk's org-creation
flow; exposed directly here so the platform is testable end-to-end without
Clerk wired up yet (docs/05-v1-roadmap.md M0/M1 boundary)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_db import get_session
from sentinel_db.models import Organization, Target
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_crypto, get_current_org
from ..schemas.organization import OrganizationCreate, OrganizationOut, OrganizationSummary
from ..services.deletion import delete_targets, refuse_if_scanning

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


@router.get("", response_model=list[OrganizationSummary])
async def list_organizations(
    session: AsyncSession = Depends(get_session),
) -> list[OrganizationSummary]:
    """Every organization, for the dashboard's organization browser. This
    deployment is an internal tool used by one small team, so anyone who can
    open it may browse all organizations (there are no user accounts)."""
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars()
    targets = (await session.execute(select(Target.organization_id, Target.root_domain))).all()
    domains: dict = {}
    for org_id, domain in targets:
        domains.setdefault(org_id, []).append(domain)
    return [
        OrganizationSummary(
            id=o.id,
            name=o.name,
            slug=o.slug,
            target_count=len(domains.get(o.id, [])),
            target_domains=sorted(domains.get(o.id, []))[:5],
        )
        for o in orgs
    ]


@router.get("/me", response_model=OrganizationOut)
async def get_my_organization(org: Organization = Depends(get_current_org)) -> Organization:
    return org


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(org_id: UUID, session: AsyncSession = Depends(get_session)) -> None:
    """Deletes the organization with all its targets, personas (and their
    stored secrets) and scans. QA #40: duplicate test orgs couldn't be
    removed. Like the organization list, this needs no X-Org-Id: the tool
    is used by one internal team."""
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found.")
    target_ids = list(
        (await session.execute(select(Target.id).where(Target.organization_id == org_id)))
        .scalars()
        .all()
    )
    await refuse_if_scanning(session, target_ids)
    await delete_targets(session, target_ids)
    await session.execute(delete(Organization).where(Organization.id == org_id))
    await session.commit()
