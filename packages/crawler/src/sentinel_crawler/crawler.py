"""PersonaCrawler: the rendered, per-persona crawl (docs/02-scan-lifecycle.md
Phase 3). Crawling as each persona *separately*, into its own SurfaceMap, is
what makes the cross-persona diff possible later — this is why an
off-the-shelf single-session crawler can't be reused unmodified for this
product (ADR-0002).

Scope for this milestone: **discover**, don't **exercise**. Forms and
non-idempotent links are recorded as endpoints (their existence is real
surface-map signal) but never submitted/clicked — filling in and firing a
form is a testing action for a later phase (docs/03), gated by the scan's
read-write policy, not something crawling does implicitly. The one thing
crawling *does* interact with is following same-origin, non-destructive
links, because that's how new pages get discovered at all.
"""

from __future__ import annotations

import contextlib
from typing import cast
from urllib.parse import urlsplit

from playwright.async_api import Browser, Page, Request, StorageState
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import DestructiveActionGuard, ScopeGuard
from sentinel_core.session_import import route_session_headers, split_session_state

from .models import DiscoveredEndpoint, DiscoverySource, SurfaceMap
from .surface_mapper import normalize_path

# Network requests worth recording as endpoints even though the crawler
# never clicked anything to trigger them — this is the "JS extraction"
# half of Phase 3: an admin API the UI calls via fetch()/XHR but never
# renders a visible link to is exactly the kind of surface a naive crawler
# misses and an authz sweep needs to know about.
_INTERESTING_RESOURCE_TYPES = frozenset({"xhr", "fetch"})


class PersonaCrawler:
    def __init__(
        self,
        *,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter,
        target_id: str,
        destructive_guard: DestructiveActionGuard | None = None,
        max_pages: int = 30,
        page_timeout_s: float = 15.0,
    ) -> None:
        self._scope_guard = scope_guard
        self._rate_limiter = rate_limiter
        self._target_id = target_id
        self._destructive_guard = destructive_guard or DestructiveActionGuard()
        self._max_pages = max_pages
        self._page_timeout_s = page_timeout_s

    async def crawl(
        self,
        browser: Browser,
        *,
        root_url: str,
        persona_id: str,
        storage_state: dict | None = None,
        seeds: list[str] | None = None,
    ) -> SurfaceMap:
        """``seeds``: extra start pages queued after ``root_url``, e.g. the
        page a persona's login landed on (/dashboard). Out-of-scope seeds
        are skipped like any other URL."""
        # Playwright's storage_state param is typed as its own StorageState
        # TypedDict; a persona's session state is stored/passed around as a
        # plain dict elsewhere in the system (see sentinel_auth.replay), so
        # this cast is the one place the two shapes have to meet.
        playwright_state, session_headers = split_session_state(storage_state)
        context = await browser.new_context(
            storage_state=cast(StorageState, playwright_state) if playwright_state else None
        )
        # A header login (sentinel_core.session_import): the header goes on
        # requests to the target's own hosts only.
        await route_session_headers(context, session_headers, urlsplit(root_url).hostname or "")
        page = await context.new_page()

        surface = SurfaceMap(root_url=root_url, persona_id=persona_id)
        seen_templates: set[tuple[str, str]] = set()  # (method, path_template) already recorded
        visited: set[str] = set()
        queue: list[str] = [root_url, *[u for u in (seeds or []) if u != root_url]]
        # Hosts whose links are followed. Starts as the root URL's host; when
        # the site redirects (abhyaasika.com -> www.abhyaasika.com, QA #37)
        # the in-scope host it landed on is added, otherwise every link on
        # the real site looks "foreign" and the crawl stops after one page.
        site_hosts: set[str] = {urlsplit(root_url).netloc}
        for seed in seeds or []:
            self._adopt_host(seed, site_hosts)

        def watch(p: Page) -> Page:
            p.on(
                "request",
                lambda req: self._record_network_request(req, persona_id, surface, seen_templates),
            )
            return p

        watch(page)

        try:
            while queue and len(visited) < self._max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue

                decision = self._scope_guard.evaluate(method="GET", url=url)
                if not decision.allowed:
                    surface.notes.append(f"Skipped out-of-scope URL: {url} ({decision.reason})")
                    continue

                check = self._destructive_guard.check(method="GET", url=url)
                if check.is_suspect:
                    surface.notes.append(f"Skipped suspected-destructive URL: {url}")
                    continue

                await self._rate_limiter.acquire(self._target_id)

                try:
                    await page.goto(url, timeout=self._page_timeout_s * 1000)
                except Exception as exc:  # noqa: BLE001 — a dead/slow link shouldn't kill the crawl
                    surface.notes.append(f"Failed to load {url}: {str(exc).splitlines()[0]}")
                    # A failed load leaves the tab on a still-settling error
                    # page, and the next goto is then "interrupted by another
                    # navigation": one dead link used to sink every page after
                    # it. Carry on in a fresh tab.
                    with contextlib.suppress(Exception):
                        await page.close()
                    page = watch(await context.new_page())
                    continue

                visited.add(url)
                landed = page.url
                if landed and landed != url:
                    visited.add(landed)
                    self._adopt_host(landed, site_hosts)
                self._record_endpoint("GET", url, "link", persona_id, surface, seen_templates)

                links = await self._extract_same_origin_links(page, site_hosts)
                forms = await self._extract_forms(page, root_url, site_hosts)

                for method, form_url in forms:
                    self._record_endpoint(
                        method, form_url, "form", persona_id, surface, seen_templates
                    )

                for link in links:
                    if link not in visited and link not in queue:
                        link_check = self._destructive_guard.check(method="GET", url=link)
                        if link_check.is_suspect:
                            # Still worth recording — a "Delete account" link
                            # is real surface-map signal — just never followed.
                            self._record_endpoint(
                                "GET", link, "link", persona_id, surface, seen_templates
                            )
                            continue
                        queue.append(link)

            surface.pages_visited = len(visited)
            return surface
        finally:
            await context.close()

    def _record_network_request(
        self,
        request: Request,
        persona_id: str,
        surface: SurfaceMap,
        seen_templates: set[tuple[str, str]],
    ) -> None:
        if request.resource_type not in _INTERESTING_RESOURCE_TYPES:
            return
        decision = self._scope_guard.evaluate(method=request.method, url=request.url)
        if not decision.allowed:
            return
        self._record_endpoint(
            request.method, request.url, "network", persona_id, surface, seen_templates
        )

    def _record_endpoint(
        self,
        method: str,
        url: str,
        source: DiscoverySource,
        persona_id: str,
        surface: SurfaceMap,
        seen_templates: set[tuple[str, str]],
    ) -> None:
        path = urlsplit(url).path or "/"
        template = normalize_path(path)
        key = (method.upper(), template)
        if key in seen_templates:
            return
        seen_templates.add(key)
        surface.endpoints.append(
            DiscoveredEndpoint(
                method=method.upper(),
                url=url,
                path_template=template,
                source=source,
                persona_id=persona_id,
            )
        )

    def _adopt_host(self, url: str, site_hosts: set[str]) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return
        if self._scope_guard.evaluate(method="GET", url=url).allowed:
            site_hosts.add(parts.netloc)

    async def _extract_same_origin_links(self, page: Page, site_hosts: set[str]) -> list[str]:
        try:
            hrefs: list[str] = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
        except Exception:  # noqa: BLE001 — page may have navigated away already
            return []

        same_origin = []
        for href in hrefs:
            parts = urlsplit(href)
            if parts.scheme not in ("http", "https"):
                continue
            if parts.netloc not in site_hosts:
                continue
            same_origin.append(href.split("#", 1)[0])  # drop in-page fragments
        return same_origin

    async def _extract_forms(
        self, page: Page, root_url: str, site_hosts: set[str]
    ) -> list[tuple[str, str]]:
        try:
            raw_forms: list[dict] = await page.eval_on_selector_all(
                "form",
                "els => els.map(e => ({"
                "action: e.action, method: (e.method || 'get').toUpperCase()"
                "}))",
            )
        except Exception:  # noqa: BLE001
            return []

        forms = []
        for form in raw_forms:
            action = form.get("action") or root_url
            parts = urlsplit(action)
            if parts.netloc and parts.netloc not in site_hosts:
                continue
            forms.append((form.get("method", "GET"), action))
        return forms
