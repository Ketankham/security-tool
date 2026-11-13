"""Persona creation and login updates (docs/01-architecture.md §6.2, §6.3).
Credential secrets are encrypted immediately with the org's data key and
never returned in any response."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_core.login_safety import login_navigation_problems
from sentinel_db.models import Credential, Organization, Persona, Target
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..celery_client import dispatch_test_login, read_test_login
from ..deps import get_crypto, get_current_org, get_owned_target, get_session
from ..schemas.persona import (
    RECIPE_STRATEGY_TO_CREDENTIAL_KIND,
    RECIPE_STRATEGY_TO_LOGIN_STRATEGY,
    SECRET_NAME,
    CredentialCreate,
    LoginTestOut,
    LoginTestStarted,
    PersonaCreate,
    PersonaLoginOut,
    PersonaLoginUpdate,
    PersonaOut,
    normalize_secret,
)
from ..services.deletion import delete_personas, refuse_if_scanning

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
        login_strategy=(
            RECIPE_STRATEGY_TO_LOGIN_STRATEGY[payload.login_recipe.strategy]
            if payload.login_recipe is not None
            else payload.login_strategy
        ),
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
    """Edit a persona's details and/or set or replace its login."""
    persona = await session.get(Persona, persona_id)
    # Same 404 for "doesn't exist" and "belongs to another target/org", so
    # persona ids can't be probed across orgs (get_owned_target already
    # scoped the target to the caller's org).
    if persona is None or persona.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Persona not found.")

    fields = payload.model_fields_set
    if payload.label is not None and payload.label.lower() != persona.label.lower():
        clash = await session.execute(
            select(Persona.id).where(
                Persona.target_id == target.id,
                func.lower(Persona.label) == payload.label.lower(),
                Persona.id != persona.id,
            )
        )
        if clash.first() is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, f"A persona named '{payload.label}' already exists."
            )
    if payload.label is not None:
        persona.label = payload.label
    if payload.role_name is not None:
        persona.role_name = payload.role_name
    if payload.trust_rank is not None:
        persona.trust_rank = payload.trust_rank
    if "tenant_key" in fields:
        persona.tenant_key = payload.tenant_key or None

    if payload.login_recipe is None and payload.credential is None:
        # Details only: the login and its last verdict are untouched.
        await session.commit()
        await session.refresh(persona)
        return persona

    stored_strategy = _strategy_of(persona.login_recipe)
    new_strategy = payload.login_recipe.strategy if payload.login_recipe else stored_strategy

    if payload.login_recipe is not None:
        _check_login_navigation(payload.login_recipe.model_dump(), target)
        # Switching e.g. form -> cookie: the stored password is not a cookie.
        if (
            payload.credential is None
            and persona.credential_id is not None
            and new_strategy != stored_strategy
        ):
            raise HTTPException(
                422,
                f"Switching this login to {new_strategy} needs {SECRET_NAME[new_strategy]} "
                "too: send 'credential' together with the login recipe.",
            )

    if payload.credential is not None:
        try:
            secret = normalize_secret(new_strategy, payload.login_recipe, payload.credential.secret)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        credential_in = CredentialCreate(
            kind=RECIPE_STRATEGY_TO_CREDENTIAL_KIND[new_strategy], secret=secret
        )
        old_credential_id = persona.credential_id
        persona.credential_id = await _store_credential(credential_in, org, session, crypto)
        if old_credential_id is not None:
            old = await session.get(Credential, old_credential_id)
            if old is not None and old.revoked_at is None:
                old.revoked_at = datetime.now(UTC)

    if payload.login_recipe is not None:
        persona.login_recipe = payload.login_recipe.model_dump()
        persona.login_recipe_version = (persona.login_recipe_version or 1) + 1
        persona.login_strategy = RECIPE_STRATEGY_TO_LOGIN_STRATEGY[new_strategy]

    # A recipe with no password can never log in; refuse rather than store a
    # persona that is guaranteed to come up "Unavailable" on the next scan.
    if persona.login_recipe is not None and persona.credential_id is None:
        missing = SECRET_NAME[new_strategy].removeprefix("a ").removeprefix("the ")
        raise HTTPException(
            422,
            f"This persona has no {missing} yet: send 'credential' together with the login recipe.",
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


@router.delete("/targets/{target_id}/personas/{persona_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_persona(
    persona_id: UUID,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Deletes the persona and its stored secret. Old scans keep their
    transcripts; they just no longer name this persona."""
    persona = await session.get(Persona, persona_id)
    if persona is None or persona.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Persona not found.")
    await refuse_if_scanning(session, [target.id])
    await delete_personas(session, [persona.id])
    await session.commit()


def _strategy_of(recipe: dict | None) -> str:
    return (recipe or {}).get("strategy") or "form"


@router.post(
    "/targets/{target_id}/personas/{persona_id}/test-login",
    response_model=LoginTestStarted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_login_test(
    persona_id: UUID,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> LoginTestStarted:
    """v1 #1: replay this persona's *saved* login once, in the worker, and
    report back (poll the GET below). Saved only: the secret never travels
    through the job queue."""
    persona = await session.get(Persona, persona_id)
    if persona is None or persona.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Persona not found.")
    if persona.login_recipe is None or persona.credential_id is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This persona has no saved login to test. Set one up first."
        )
    test_id = dispatch_test_login(str(persona.id))
    if test_id is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The login test could not be queued (the job queue is unreachable). Try again shortly.",
        )
    return LoginTestStarted(test_id=test_id)


@router.get(
    "/targets/{target_id}/personas/{persona_id}/test-login/{test_id}",
    response_model=LoginTestOut,
)
async def get_login_test(
    persona_id: UUID,
    test_id: UUID,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> LoginTestOut:
    persona = await session.get(Persona, persona_id)
    if persona is None or persona.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Persona not found.")
    result = read_test_login(str(test_id))
    if result is None:
        return LoginTestOut(status="pending")
    # A test id only ever answers for the persona it was started for, so
    # ids can't be used to read another org's results. (A worker-level
    # failure carries no persona_id and no data, just the error.)
    if "persona_id" in result and result["persona_id"] != str(persona.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Login test not found.")
    return LoginTestOut(
        status="done",
        success=bool(result.get("success")),
        error=result.get("error"),
        final_url=result.get("final_url"),
        screenshot_jpeg_b64=result.get("screenshot_jpeg_b64"),
        duration_s=result.get("duration_s"),
        checked_at=result.get("checked_at"),
    )


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
