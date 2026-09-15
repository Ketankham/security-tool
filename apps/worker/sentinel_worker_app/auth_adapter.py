"""Bridges DB-persisted persona data (JSON login_recipe, encrypted
credential) into sentinel_auth's dataclasses and its replay/oracle calls.
Kept as its own module so scan_runner reads as orchestration, not plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from playwright.async_api import Browser
from sentinel_auth import (
    Credential,
    LoginRecipe,
    LoginReplayer,
    LoginStep,
    PersonaSession,
    SessionOracle,
    SuccessAssertion,
    establish_session_oracle,
)
from sentinel_core.crypto import EnvelopeCrypto
from sentinel_core.http_engine import HttpEngine
from sentinel_db.models import Persona


def build_login_recipe(raw: dict) -> LoginRecipe:
    steps = tuple(
        LoginStep(
            action=s["action"],
            selector=s.get("selector"),
            value=s.get("value"),
            credential_ref=s.get("credential_ref"),
            timeout_s=s.get("timeout_s", 10.0),
        )
        for s in raw["steps"]
    )
    assertion = SuccessAssertion(
        kind=raw["success_assertion"]["kind"],
        value=raw["success_assertion"]["value"],
        timeout_s=raw["success_assertion"].get("timeout_s", 10.0),
    )
    return LoginRecipe(
        start_url=raw["start_url"],
        steps=steps,
        success_assertion=assertion,
        strategy=raw.get("strategy", "form"),
        max_duration_s=raw.get("max_duration_s", 30.0),
    )


@dataclass(frozen=True, slots=True)
class PersonaAuthResult:
    available: bool
    unavailable_reason: str | None
    storage_state: dict | None
    session_oracle: SessionOracle | None
    oracle_detail: str | None


async def establish_persona(
    *,
    persona: Persona,
    browser: Browser,
    crypto: EnvelopeCrypto,
    org_data_key: bytes,
    engine: HttpEngine,
    oracle_probe_url: str,
) -> PersonaAuthResult:
    def _unavailable(reason: str) -> PersonaAuthResult:
        return PersonaAuthResult(
            available=False,
            unavailable_reason=reason,
            storage_state=None,
            session_oracle=None,
            oracle_detail=None,
        )

    if not persona.login_recipe:
        return _unavailable("No login recipe configured for this persona.")
    if persona.credential is None:
        return _unavailable("No credential configured for this persona.")

    recipe = build_login_recipe(persona.login_recipe)
    secret_ref = next(
        (s.credential_ref for s in recipe.steps if s.action == "fill_secret" and s.credential_ref),
        None,
    )
    if secret_ref is None:
        return _unavailable("Login recipe has no fill_secret step to attach the credential to.")

    plaintext = crypto.decrypt(org_data_key, persona.credential.ciphertext).decode()
    credentials = {secret_ref: Credential(ref=secret_ref, secret=plaintext)}

    replayer = LoginReplayer(browser)
    replay_result = await replayer.replay(recipe, credentials=credentials)
    if not replay_result.success:
        return _unavailable(f"Login replay failed: {replay_result.error}")

    host = urlsplit(recipe.start_url).hostname
    session = PersonaSession(str(persona.id), replay_result.storage_state, target_host=host)

    # A persona whose login succeeds but whose oracle can't be established
    # is still available for crawling — it's authz-confidence, not session
    # validity, that's capped (docs/04-edge-cases.md §B3). Don't conflate
    # the two into one boolean.
    oracle_result = await establish_session_oracle(engine, session, probe_url=oracle_probe_url)

    return PersonaAuthResult(
        available=True,
        unavailable_reason=None,
        storage_state=replay_result.storage_state,
        session_oracle=oracle_result.oracle,
        oracle_detail=oracle_result.detail,
    )
