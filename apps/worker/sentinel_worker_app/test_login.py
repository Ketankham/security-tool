"""The dashboard's "Test login" button (v1 #1): replay one persona's saved
login exactly the way a scan would, and report back what happened, where the
browser ended up, and a screenshot of that page.

Runs in the worker (the API image has no browser) on the "logins" queue, so
it answers in seconds even while a long scan holds the scan worker. The
outcome also updates the persona's Available / Unavailable status, the same
fields a scan's login step sets.
"""

from __future__ import annotations

import base64
import time
import uuid
from datetime import UTC, datetime

import structlog
from playwright.async_api import async_playwright
from sentinel_auth.browser import chromium_launch_kwargs
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_db import open_session
from sentinel_db.models import Organization, Persona, Target
from sqlalchemy.orm import selectinload

from .auth_adapter import establish_persona
from .config import get_settings

log = structlog.get_logger(__name__)


async def run_test_login(persona_id: str) -> dict:
    started = time.monotonic()

    def outcome(success: bool, error: str | None = None, **extra: object) -> dict:
        return {
            "persona_id": persona_id,
            "success": success,
            "error": error,
            "final_url": extra.get("final_url"),
            "screenshot_jpeg_b64": extra.get("screenshot_jpeg_b64"),
            "duration_s": round(time.monotonic() - started, 1),
            "checked_at": datetime.now(UTC).isoformat(),
        }

    settings = get_settings()
    if not settings.kms_master_key:
        return outcome(False, "KMS_MASTER_KEY is not configured on the worker.")

    async with open_session() as session:
        persona = await session.get(
            Persona, uuid.UUID(persona_id), options=[selectinload(Persona.credential)]
        )
        if persona is None:
            return outcome(False, "This persona no longer exists.")
        target = await session.get(Target, persona.target_id)
        org = await session.get(Organization, target.organization_id) if target else None
        if target is None or org is None:
            return outcome(False, "This persona's target no longer exists.")

        crypto = EnvelopeCrypto(LocalMasterKeyProvider([settings.kms_master_key.encode()]))
        org_data_key = crypto.unwrap_data_key(org.wrapped_data_key)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**chromium_launch_kwargs())
            try:
                result = await establish_persona(
                    persona=persona,
                    browser=browser,
                    crypto=crypto,
                    org_data_key=org_data_key,
                    engine=None,
                    oracle_probe_url=f"https://{target.root_domain}/",
                    target_root_domain=target.root_domain,
                    capture_screenshot=True,
                )
            finally:
                await browser.close()

        persona.is_available = result.available
        persona.unavailable_reason = result.unavailable_reason
        await session.commit()

    log.info("test_login.done", persona_id=persona_id, success=result.available)
    return outcome(
        result.available,
        result.unavailable_reason,
        final_url=result.final_url,
        screenshot_jpeg_b64=(
            base64.b64encode(result.screenshot).decode() if result.screenshot else None
        ),
    )
