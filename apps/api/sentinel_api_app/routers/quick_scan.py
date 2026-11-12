"""POST /quick-scan: the one-shot "give me a URL, get a report" flow.

This deliberately bypasses two things the rest of the API requires: an
authenticated org (X-Org-Id) to create a target, and the ownership-
verification + authorization-acceptance gate (docs/06-safety-legal-abuse.md
§1) before a target becomes scannable. That gate exists because scanning a
domain nobody gave permission to test is not a formality to skip — it's the
product's legal posture. This endpoint is off by default
(``settings.enable_quick_scan``) precisely so a real, customer-facing
deployment doesn't accidentally ship it; it exists for local/dev testing
where the caller already knows they're allowed to scan whatever URL they
hand in.

Every quick-scanned target lands under one auto-provisioned dev org (found-
or-created by a fixed slug) rather than a fresh org per call, so repeated
scans of the same domain accumulate under one place instead of scattering.
The response includes ``org_id`` so the caller can use the *normal*,
authenticated endpoints (GET /scans/{id}, GET /scans/{id}/report) to poll
and read results — this endpoint only skips onboarding, not the read-side
authorization model.

Scope today (docs/05-v1-roadmap.md M2): no personas are created, so the
resulting report is recon + crawl + surface mapping only — the
authorization engine has nothing to compare identities against without at
least one authenticated persona. See sentinel_reporter.ScanReport's
scope_note for the same caveat surfaced in the report itself.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_db.models import Organization, Scan, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..celery_client import dispatch_scan
from ..config import Settings, get_settings
from ..deps import get_crypto, get_session
from ..schemas.quick_scan import QuickScanCreate, QuickScanOut

router = APIRouter(tags=["quick-scan"])

_QUICK_SCAN_ORG_SLUG = "quick-scan-dev"
_QUICK_SCAN_ORG_NAME = "Quick Scan (dev)"


def _extract_root_domain(url: str) -> str:
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    if not parsed.hostname:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Could not parse a hostname from {url!r}."
        )
    return parsed.hostname


async def _get_or_create_quick_scan_org(
    session: AsyncSession, crypto: EnvelopeCrypto
) -> Organization:
    existing = await session.execute(
        select(Organization).where(Organization.slug == _QUICK_SCAN_ORG_SLUG)
    )
    org = existing.scalar_one_or_none()
    if org is not None:
        return org

    data_key = crypto.generate_data_key()
    org = Organization(
        name=_QUICK_SCAN_ORG_NAME,
        slug=_QUICK_SCAN_ORG_SLUG,
        wrapped_data_key=crypto.wrap_data_key(data_key),
    )
    session.add(org)
    await session.flush()
    return org


async def _get_or_create_target(
    session: AsyncSession, org: Organization, root_domain: str
) -> Target:
    existing = await session.execute(
        select(Target).where(Target.organization_id == org.id, Target.root_domain == root_domain)
    )
    target = existing.scalar_one_or_none()
    if target is not None:
        return target

    target = Target(
        organization_id=org.id,
        root_domain=root_domain,
        display_name=root_domain,
        is_production=False,
        # The dev-mode bypass this whole module exists for — see the module
        # docstring. Never set these two directly outside this endpoint.
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()
    return target


@router.post("/quick-scan", response_model=QuickScanOut, status_code=status.HTTP_201_CREATED)
async def create_quick_scan(
    payload: QuickScanCreate,
    session: AsyncSession = Depends(get_session),
    crypto: EnvelopeCrypto = Depends(get_crypto),
    settings: Settings = Depends(get_settings),
) -> QuickScanOut:
    if not settings.enable_quick_scan:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Quick-scan mode is disabled on this deployment. It bypasses ownership "
            "verification and is intended for local/dev use only — see "
            "routers/quick_scan.py and docs/06-safety-legal-abuse.md §1.",
        )

    root_domain = _extract_root_domain(payload.url)
    org = await _get_or_create_quick_scan_org(session, crypto)
    target = await _get_or_create_target(session, org, root_domain)
    await session.commit()

    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    dispatch_scan(str(scan.id))

    return QuickScanOut(
        scan_id=scan.id,
        org_id=org.id,
        target_id=target.id,
        root_domain=root_domain,
        state=scan.state,
    )
