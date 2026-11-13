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
from sentinel_core.login_safety import login_navigation_problems
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
        for s in raw.get("steps") or []
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
        strategy=raw.get("strategy") or "form",
        max_duration_s=raw.get("max_duration_s", 30.0),
        header_name=raw.get("header_name"),
    )


@dataclass(frozen=True, slots=True)
class PersonaAuthResult:
    available: bool
    unavailable_reason: str | None
    storage_state: dict | None
    session_oracle: SessionOracle | None
    oracle_detail: str | None
    # For Test login (never persisted): where the browser ended up, a JPEG.
    final_url: str | None = None
    screenshot: bytes | None = None


async def establish_persona(
    *,
    persona: Persona,
    browser: Browser,
    crypto: EnvelopeCrypto,
    org_data_key: bytes,
    engine: HttpEngine | None,
    oracle_probe_url: str,
    target_root_domain: str,
    capture_screenshot: bool = False,
) -> PersonaAuthResult:
    """Logs one persona in. ``engine=None`` skips the session-oracle step
    (Test login only needs to know whether the login works)."""

    def _unavailable(
        reason: str, final_url: str | None = None, screenshot: bytes | None = None
    ) -> PersonaAuthResult:
        return PersonaAuthResult(
            available=False,
            # Persona.unavailable_reason is a String(500).
            unavailable_reason=reason if len(reason) <= 500 else reason[:497] + "...",
            storage_state=None,
            session_oracle=None,
            oracle_detail=None,
            final_url=final_url,
            screenshot=screenshot,
        )

    if not persona.login_recipe:
        return _unavailable("No login recipe configured for this persona.")
    if persona.credential is None:
        return _unavailable("No credential configured for this persona.")

    # Re-checked here, before the secret is decrypted, so a recipe saved
    # before the API validated login URLs (QA #23) can never type the
    # password into a non-http(s) or off-target page, and a pasted session
    # is never sent off the target.
    problems = login_navigation_problems(persona.login_recipe, target_root_domain)
    if problems:
        return _unavailable("Login blocked: " + "; ".join(problems))

    recipe = build_login_recipe(persona.login_recipe)
    credentials: dict[str, Credential] = {}
    session_secret: str | None = None
    if recipe.strategy == "form":
        secret_ref = next(
            (
                s.credential_ref
                for s in recipe.steps
                if s.action == "fill_secret" and s.credential_ref
            ),
            None,
        )
        if secret_ref is None:
            return _unavailable("Login recipe has no fill_secret step to attach the credential to.")
        plaintext = crypto.decrypt(org_data_key, persona.credential.ciphertext).decode()
        credentials = {secret_ref: Credential(ref=secret_ref, secret=plaintext)}
    else:
        session_secret = crypto.decrypt(org_data_key, persona.credential.ciphertext).decode()

    replayer = LoginReplayer(browser)
    replay_result = await replayer.replay(
        recipe,
        credentials=credentials,
        session_secret=session_secret,
        target_root_domain=target_root_domain,
        capture_screenshot=capture_screenshot,
    )
    if not replay_result.success:
        return _unavailable(
            f"Login replay failed: {replay_result.error}",
            replay_result.final_url,
            replay_result.screenshot,
        )

    oracle: SessionOracle | None = None
    oracle_detail: str | None = None
    if engine is not None:
        host = urlsplit(recipe.start_url).hostname
        session = PersonaSession(
            str(persona.id), replay_result.storage_state or {}, target_host=host
        )
        # A persona whose login succeeds but whose oracle can't be established
        # is still available for crawling — it's authz-confidence, not session
        # validity, that's capped (docs/04-edge-cases.md §B3). Don't conflate
        # the two into one boolean.
        try:
            oracle_result = await establish_session_oracle(
                engine, session, probe_url=oracle_probe_url
            )
            oracle, oracle_detail = oracle_result.oracle, oracle_result.detail
        except Exception as exc:  # noqa: BLE001 — an unreachable probe URL must not end the scan
            why = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
            oracle_detail = (
                f"Logged in, but couldn't check whether the session stays alive "
                f"({oracle_probe_url} failed: {why}). "
                "Access-control results for this persona are less certain."
            )

    return PersonaAuthResult(
        available=True,
        unavailable_reason=None,
        storage_state=replay_result.storage_state,
        session_oracle=oracle,
        oracle_detail=oracle_detail,
        final_url=replay_result.final_url,
        screenshot=replay_result.screenshot,
    )
