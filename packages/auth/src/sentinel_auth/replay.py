"""Deterministic replay of a recorded LoginRecipe (docs/01-architecture.md
§6.4, docs/02-scan-lifecycle.md Phase 2).

Recording (AI-assisted DOM-driven recipe synthesis) is a separate, later
concern (docs/05-v1-roadmap.md M1/M2 — the AI login recorder). This module
is the half that has to be rock solid regardless: replaying an already-
recorded recipe, byte-for-byte the same way every scan, every time.

Three strategies (v1 #1):

- ``form``: open ``start_url``, run the steps (one types the password),
  check the success assertion;
- ``cookie``: put the pasted cookies in a fresh browser, open ``start_url``
  (a page only a logged-in user sees) and check the success assertion;
- ``header``: the same, with the pasted header added to every request to the
  target's own hosts.

Every outcome comes back as a LoginReplayResult (never an exception), with
the URL the browser ended on and, when asked, a screenshot — that is what
makes a failed login debuggable from the dashboard's Test login button.
"""

from __future__ import annotations

import contextlib
import ipaddress
import time
from urllib.parse import urlsplit

from playwright.async_api import Browser, BrowserContext, Page
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from sentinel_core.session_import import (
    SESSION_HEADERS_KEY,
    check_header_name,
    check_header_value,
    parse_cookie_header,
    route_session_headers,
)

from .browser import chromium_launch_kwargs
from .models import Credential, LoginRecipe, LoginReplayResult, LoginStep, SuccessAssertion

# After a URL check first passes, how long to let redirects/JS settle before
# checking again. Without it, opening /dashboard with a dead session "passes"
# url_not_contains=/sign-in in the instant before the app redirects.
_SETTLE_MS = 5000


class _AssertionFailed(Exception):
    pass


class LoginReplayer:
    def __init__(self, browser: Browser) -> None:
        self._browser = browser

    async def replay(
        self,
        recipe: LoginRecipe,
        *,
        credentials: dict[str, Credential] | None = None,
        session_secret: str | None = None,
        target_root_domain: str | None = None,
        capture_screenshot: bool = False,
    ) -> LoginReplayResult:
        """``credentials`` feed a form recipe's fill_secret steps;
        ``session_secret`` is the pasted cookie string / header value of a
        cookie or header login. ``target_root_domain`` scopes where pasted
        cookies/headers are sent (default: the start URL's host)."""
        credentials = credentials or {}
        start = time.monotonic()
        scope = target_root_domain or urlsplit(recipe.start_url).hostname or ""
        context = await self._browser.new_context()
        page = await context.new_page()
        error: str | None = None
        storage_state: dict | None = None

        try:
            session_headers = await self._prepare_session(context, recipe, session_secret, scope)
            await page.goto(recipe.start_url, timeout=recipe.max_duration_s * 1000)

            for step in recipe.steps:
                await self._run_step(page, step, credentials)

            if not await self._check_assertion(page, recipe.success_assertion):
                raise _AssertionFailed(_describe_failed_assertion(recipe.success_assertion))

            # Playwright types this as its own StorageState TypedDict;
            # cast to a plain dict since that's what we persist/encrypt and
            # what PersonaSession expects.
            storage_state = dict(await context.storage_state())
            if session_headers:
                storage_state[SESSION_HEADERS_KEY] = session_headers

        except _AssertionFailed as exc:
            error = str(exc)
        except ValueError as exc:  # a pasted cookie/header that can't be used
            error = str(exc)
        except PlaywrightTimeoutError as exc:
            error = f"timeout: {_first_line(exc)}"
        except KeyError as exc:
            error = f"missing credential for ref {exc}"
        except PlaywrightError as exc:
            # e.g. a malformed CSS selector typed into the dashboard's login
            # form, or the login page failing to load. A hand-written recipe
            # being wrong is an expected, reportable outcome ("Unavailable:
            # ..."), not a crash of the auth phase. (TimeoutError subclasses
            # Error, so the more specific handler above still wins.)
            error = f"login step failed: {_first_line(exc)}"

        final_url, screenshot = await _snapshot(page, capture_screenshot)
        await context.close()

        if error is not None and final_url:
            error = f"{error} (the browser ended on {final_url})"
        return LoginReplayResult(
            success=error is None,
            storage_state=storage_state if error is None else None,
            error=error,
            duration_s=time.monotonic() - start,
            final_url=final_url,
            screenshot=screenshot,
        )

    async def _prepare_session(
        self,
        context: BrowserContext,
        recipe: LoginRecipe,
        session_secret: str | None,
        scope: str,
    ) -> dict[str, str]:
        """Loads a pasted cookie/header into the context. Returns the headers
        to carry into the scan (header strategy only)."""
        if recipe.strategy == "form":
            return {}
        if not session_secret:
            raise ValueError(f"No {recipe.strategy} value is stored for this login.")

        if recipe.strategy == "cookie":
            parts = urlsplit(recipe.start_url)
            if _is_ip(scope):
                # Browsers only keep host-only cookies for IP addresses.
                where: dict = {"url": f"{parts.scheme}://{parts.netloc}/"}
            else:
                # Leading dot: the target's root domain and its subdomains
                # (e.g. app. and api.), nothing else.
                where = {"domain": "." + scope, "path": "/", "secure": parts.scheme == "https"}
            await context.add_cookies(
                [
                    {"name": name, "value": value, **where}
                    for name, value in parse_cookie_header(session_secret)
                ]
            )
            return {}

        name = check_header_name(recipe.header_name or "Authorization")
        headers = {name: check_header_value(session_secret, name)}
        await route_session_headers(context, headers, scope)
        return headers

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

    async def _check_assertion(self, page: Page, assertion: SuccessAssertion) -> bool:
        timeout_ms = assertion.timeout_s * 1000
        try:
            if assertion.kind in ("url_contains", "url_not_contains"):
                want = assertion.kind == "url_contains"

                def ok(url: str) -> bool:
                    return (assertion.value in url) is want

                await page.wait_for_url(ok, timeout=timeout_ms)
                # Let redirects / client-side routing finish, then re-check:
                # the URL must still satisfy the check once the page settles.
                await _settle(page)
                return ok(page.url)
            if assertion.kind == "selector_visible":
                await page.wait_for_selector(assertion.value, state="visible", timeout=timeout_ms)
                return True
            if assertion.kind == "selector_hidden":
                await page.wait_for_selector(assertion.value, state="hidden", timeout=timeout_ms)
                return True
        except PlaywrightTimeoutError:
            return False
        return False  # pragma: no cover — exhaustive over SuccessAssertion.kind


def _describe_failed_assertion(assertion: SuccessAssertion) -> str:
    what = {
        "url_contains": f"the URL never contained {assertion.value!r}",
        "url_not_contains": f"the URL still contained {assertion.value!r}",
        "selector_visible": f"{assertion.value!r} never appeared",
        "selector_hidden": f"{assertion.value!r} never went away",
    }.get(assertion.kind, f"{assertion.kind}={assertion.value!r}")
    return f"Success check failed: {what}"


async def _settle(page: Page) -> None:
    # A page that never goes idle (polling, websockets) is fine.
    with contextlib.suppress(PlaywrightTimeoutError):
        await page.wait_for_load_state("networkidle", timeout=_SETTLE_MS)


async def _snapshot(page: Page, capture: bool) -> tuple[str | None, bytes | None]:
    """Best effort: a page that crashed may give neither."""
    url: str | None = None
    shot: bytes | None = None
    with contextlib.suppress(PlaywrightError):  # a closed page
        url = page.url if page.url and page.url != "about:blank" else None
    if capture:
        with contextlib.suppress(PlaywrightError):
            shot = await page.screenshot(type="jpeg", quality=60, timeout=5000)
    return url, shot


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return text.splitlines()[0][:300] if text else type(exc).__name__


async def new_browser(playwright_instance) -> Browser:
    return await playwright_instance.chromium.launch(**chromium_launch_kwargs())
