"""Persona creation (docs/01-architecture.md §6.2, §6.3). Credential
secrets are encrypted immediately with the org's data key and never
returned in any response."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_db.models import Credential, Organization, Persona, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_crypto, get_current_org, get_owned_target, get_session
from ..schemas.persona import PersonaCreate, PersonaOut

router = APIRouter(tags=["personas"])


@router.post(
    "/targets/{target_id}/personas",
    response_model=PersonaOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_persona(
    payload: PersonaCreate,
    target: Target = Depends(get_owned_target),
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
    crypto: EnvelopeCrypto = Depends(get_crypto),
) -> Persona:
    credential_id = None
    if payload.credential is not None:
        data_key = crypto.unwrap_data_key(org.wrapped_data_key)
        ciphertext = crypto.encrypt(data_key, payload.credential.secret.encode())
        credential = Credential(kind=payload.credential.kind, ciphertext=ciphertext)
        session.add(credential)
        await session.flush()
        credential_id = credential.id

    persona = Persona(
        target_id=target.id,
        label=payload.label,
        role_name=payload.role_name,
        trust_rank=payload.trust_rank,
        tenant_key=payload.tenant_key,
        login_strategy=payload.login_strategy,
        credential_id=credential_id,
        expected_denied=payload.expected_denied,
    )
    session.add(persona)
    await session.commit()
    await session.refresh(persona)
    return persona


@router.get("/targets/{target_id}/personas", response_model=list[PersonaOut])
async def list_personas(
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> list[Persona]:
    result = await session.execute(select(Persona).where(Persona.target_id == target.id))
    return list(result.scalars().all())
