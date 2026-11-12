"""Persona creation and login updates (docs/01-architecture.md §6.2, §6.3).
Credential secrets are encrypted immediately with the org's data key and
never returned in any response."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_core.login_safety import login_navigation_problems
from sentinel_db.enums import LoginStrategy
from sentinel_db.models import Credential, Organization, Persona, Target
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_crypto, get_current_org, get_owned_target, get_session
from ..schemas.persona import (
    CredentialCreate,
    PersonaCreate,
    PersonaLoginOut,
    PersonaLoginUpdate,
    PersonaOut,
)

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
    if payload.login_recipe is not None:
        _check_login_navigation(payload.login_recipe.model_dump(), target)

    duplicate = await session.execute(
        select(Persona.id).where(
            Persona.target_id == target.id, func.lower(Persona.label) == payload.label.lower()
        )
    )
    if duplicate.first() is not None:
        # Labels are how findings name who could reach what; two "Admin"s
        # would make a report ambiguous (QA #19).
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"A persona named '{payload.label}' already exists."
        )

    credential_id = None
    if payload.credential is not None:
        credential_id = await _store_credential(payload.credential, org, session, crypto)

    persona = Persona(
        target_id=target.id,
        label=payload.label,
        role_name=payload.role_name,
        trust_rank=payload.trust_rank,
        tenant_key=payload.tenant_key,
        login_strategy=payload.login_strategy
        or (LoginStrategy.FORM if payload.login_recipe is not None else None),
        credential_id=credential_id,
        login_recipe=payload.login_recipe.model_dump() if payload.login_recipe else None,
        expected_denied=payload.expected_denied,
    )
    session.add(persona)
    await session.commit()
    await session.refresh(persona)
    return persona


@router.get("/targets/{target_id}/personas/{persona_id}/login", response_model=PersonaLoginOut)
async def get_persona_login(
    persona_id: UUID,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> PersonaLoginOut:
    persona = await session.get(Persona, persona_id)
    if persona is None or persona.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Persona not found.")
    return PersonaLoginOut(
        login_recipe=persona.login_recipe, has_password=persona.credential_id is not None
    )


@router.patch("/targets/{target_id}/personas/{persona_id}", response_model=PersonaOut)
async def update_persona_login(
    persona_id: UUID,
    payload: PersonaLoginUpdate,
    target: Target = Depends(get_owned_target),
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
    crypto: EnvelopeCrypto = Depends(get_crypto),
) -> Persona:
    """Set or replace a persona's login recipe and/or password."""
    persona = await session.get(Persona, persona_id)
    # Same 404 for "doesn't exist" and "belongs to another target/org", so
    # persona ids can't be probed across orgs (get_owned_target already
    # scoped the target to the caller's org).
    if persona is None or persona.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Persona not found.")

    if payload.credential is not None:
        old_credential_id = persona.credential_id
        persona.credential_id = await _store_credential(payload.credential, org, session, crypto)
        if old_credential_id is not None:
            old = await session.get(Credential, old_credential_id)
            if old is not None and old.revoked_at is None:
                old.revoked_at = datetime.now(UTC)

    if payload.login_recipe is not None:
        _check_login_navigation(payload.login_recipe.model_dump(), target)
        persona.login_recipe = payload.login_recipe.model_dump()
        persona.login_recipe_version = (persona.login_recipe_version or 1) + 1
        persona.login_strategy = LoginStrategy.FORM

    # A recipe with no password can never log in; refuse rather than store a
    # persona that is guaranteed to come up "Unavailable" on the next scan.
    if persona.login_recipe is not None and persona.credential_id is None:
        raise HTTPException(
            422,
            "This persona has no password yet: send 'credential' together with the login recipe.",
        )

    # Last run's "Unavailable" verdict was about the old login; clear it so
    # the dashboard shows the persona as pending until the next scan re-checks.
    persona.is_available = True
    persona.unavailable_reason = None
    # Any cached session belongs to the old login.
    persona.session_state_ciphertext = None
    persona.session_state_updated_at = None
    persona.session_state_expires_at = None

    await session.commit()
    await session.refresh(persona)
    return persona


def _check_login_navigation(recipe: dict, target: Target) -> None:
    """QA #23: a recipe types the persona's real password into the pages it
    opens, so they must be http(s) pages on the target (or explicitly
    confirmed off-domain, e.g. SSO). Checked again by the worker at replay."""
    problems = login_navigation_problems(recipe, target.root_domain)
    if problems:
        raise HTTPException(422, "; ".join(problems))


async def _store_credential(
    credential_in: CredentialCreate,
    org: Organization,
    session: AsyncSession,
    crypto: EnvelopeCrypto,
) -> UUID:
    data_key = crypto.unwrap_data_key(org.wrapped_data_key)
    ciphertext = crypto.encrypt(data_key, credential_in.secret.encode())
    credential = Credential(kind=credential_in.kind, ciphertext=ciphertext)
    session.add(credential)
    await session.flush()
    return credential.id


@router.get("/targets/{target_id}/personas", response_model=list[PersonaOut])
async def list_personas(
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> list[Persona]:
    result = await session.execute(select(Persona).where(Persona.target_id == target.id))
    return list(result.scalars().all())
