"""Deterministic replay of a recorded LoginRecipe (docs/01-architecture.md
§6.4, docs/02-scan-lifecycle.md Phase 2).

Recording (AI-assisted DOM-driven recipe synthesis) is a separate, later
concern (docs/05-v1-roadmap.md M1/M2 — the AI login recorder). This module
is the half that has to be rock solid regardless: replaying an already-
recorded recipe, byte-for-byte the same way every scan, every time.
"""

from __future__ import annotations

import time

from playwright.async_api import Browser
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from .browser import chromium_launch_kwargs
from .models import Credential, LoginRecipe, LoginReplayResult, LoginStep


class LoginReplayer:
    def __init__(self, browser: Browser) -> None:
        self._browser = browser

    async def replay(
        self, recipe: LoginRecipe, *, credentials: dict[str, Credential] | None = None
    ) -> LoginReplayResult:
        credentials = credentials or {}
        start = time.monotonic()
        context = await self._browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(recipe.start_url, timeout=recipe.max_duration_s * 1000)

            for step in recipe.steps:
                await self._run_step(page, step, credentials)

            success = await self._check_assertion(page, recipe.success_assertion)
            if not success:
                return LoginReplayResult(
                    success=False,
                    error=(
                        f"Success assertion failed: {recipe.success_assertion.kind}="
                        f"{recipe.success_assertion.value!r}"
                    ),
                    duration_s=time.monotonic() - start,
                )

            # Playwright types this as its own StorageState TypedDict;
            # cast to a plain dict since that's what we persist/encrypt and
            # what PersonaSession expects.
            storage_state = dict(await context.storage_state())
            return LoginReplayResult(
                success=True, storage_state=storage_state, duration_s=time.monotonic() - start
            )

        except PlaywrightTimeoutError as exc:
            return LoginReplayResult(
                success=False, error=f"timeout: {exc}", duration_s=time.monotonic() - start
            )
        except KeyError as exc:
            return LoginReplayResult(
                success=False,
                error=f"missing credential for ref {exc}",
                duration_s=time.monotonic() - start,
            )
        finally:
            await context.close()

    async def _run_step(self, page, step: LoginStep, credentials: dict[str, Credential]) -> None:
        timeout_ms = step.timeout_s * 1000

        if step.action == "goto":
            assert step.value is not None
            await page.goto(step.value, timeout=timeout_ms)
        elif step.action == "fill":
            assert step.selector is not None and step.value is not None
            await page.fill(step.selector, step.value, timeout=timeout_ms)
        elif step.action == "fill_secret":
            assert step.selector is not None and step.credential_ref is not None
            secret = credentials[step.credential_ref].secret
            await page.fill(step.selector, secret, timeout=timeout_ms)
        elif step.action == "click":
            assert step.selector is not None
            await page.click(step.selector, timeout=timeout_ms)
        elif step.action == "wait_for_selector":
            assert step.selector is not None
            await page.wait_for_selector(step.selector, timeout=timeout_ms)
        elif step.action == "wait_for_url":
            assert step.value is not None
            await page.wait_for_url(step.value, timeout=timeout_ms)
        else:  # pragma: no cover — exhaustive over StepAction
            raise ValueError(f"Unknown login step action: {step.action}")

    async def _check_assertion(self, page, assertion) -> bool:
        try:
            if assertion.kind == "url_contains":
                await page.wait_for_url(
                    f"**{assertion.value}**", timeout=assertion.timeout_s * 1000
                )
                return True
            if assertion.kind == "selector_visible":
                await page.wait_for_selector(
                    assertion.value, state="visible", timeout=assertion.timeout_s * 1000
                )
                return True
            if assertion.kind == "selector_hidden":
                await page.wait_for_selector(
                    assertion.value, state="hidden", timeout=assertion.timeout_s * 1000
                )
                return True
        except PlaywrightTimeoutError:
            return False
        return False  # pragma: no cover — exhaustive over SuccessAssertion.kind


async def new_browser(playwright_instance) -> Browser:
    return await playwright_instance.chromium.launch(**chromium_launch_kwargs())
