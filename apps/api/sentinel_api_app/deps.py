"""FastAPI dependencies.

``get_current_org`` is a deliberate placeholder: real auth is Clerk
(docs/01-architecture.md §3.2), which needs a Clerk project, JWKS
verification, and org/session management infra this milestone doesn't set
up. Standing in for it with an explicit, loud header-based dependency keeps
every route's authorization shape correct today (every route requires an
org) so swapping in real Clerk verification later touches one function, not
every router.
"""

from __future__ import annotations

from functools import lru_cache
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_db import get_session
from sentinel_db.models import Organization, Target
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings

__all__ = ["get_current_org", "get_crypto", "get_owned_target", "SessionDep"]

SessionDep = get_session


async def get_current_org(
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
    session: AsyncSession = Depends(get_session),
) -> Organization:
    """DEV-ONLY auth stand-in — see module docstring. Replace with Clerk JWT
    verification before this leaves M1."""
    if not x_org_id:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing X-Org-Id header (dev auth stand-in for Clerk — see app.deps).",
        )
    try:
        org_uuid = UUID(x_org_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Org-Id is not a valid UUID.") from exc

    org = await session.get(Organization, org_uuid)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found.")
    return org


@lru_cache
def _master_key_provider(kms_master_key: str) -> LocalMasterKeyProvider:
    if not kms_master_key:
        raise RuntimeError(
            "KMS_MASTER_KEY is not configured. Generate one with "
            '`python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"` and set it in .env.'
        )
    return LocalMasterKeyProvider([kms_master_key.encode()])


def get_crypto(settings: Settings = Depends(get_settings)) -> EnvelopeCrypto:
    return EnvelopeCrypto(_master_key_provider(settings.kms_master_key))


async def get_owned_target(
    target_id: UUID,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> Target:
    """Every sub-resource route (personas, scans, scope rules) depends on
    this rather than a bare ``session.get(Target, id)`` — it's the one place
    that enforces a target belongs to the caller's org, so it can't be
    forgotten on a new route."""
    target = await session.get(Target, target_id)
    if target is None or target.organization_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found.")
    return target
