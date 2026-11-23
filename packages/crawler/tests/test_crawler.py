"""PersonaCrawler against a real server + real browser (packages/crawler/
tests/fixtures/mini_app.py) — no mocking. Covers the specific claims that
matter for this product: same-origin discovery, out-of-scope exclusion,
the destructive-action guard, path-template collapsing, and the JS-only
endpoint that a static-HTML-only crawler would never find.
"""

from __future__ import annotations

from fakeredis.aioredis import FakeRedis
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_crawler import PersonaCrawler


def _crawler(mini_app_server: str, **kwargs) -> PersonaCrawler:
    host = mini_app_server.split("://", 1)[1].split(":")[0]
    scope_guard = ScopeGuard(allowed_hosts={host}, target_ownership_verified=True)
    rate_limiter = RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000)
    return PersonaCrawler(
        scope_guard=scope_guard, rate_limiter=rate_limiter, target_id="target-1", **kwargs
    )


async def test_crawl_discovers_same_origin_pages(mini_app_server, browser):
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    visited_paths = {e.path_template for e in surface.endpoints if e.source == "link"}
    assert "/" in visited_paths
    assert "/profile" in visited_paths
    assert "/about" in visited_paths
    assert (
        surface.pages_visited == 5
    )  # /, /profile, /about, /users/42, /users/7 — NOT /account/delete


async def test_crawl_never_follows_destructive_link_but_still_records_it(mini_app_server, browser):
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    delete_endpoints = [e for e in surface.endpoints if e.path_template == "/account/delete"]
    assert len(delete_endpoints) == 1  # recorded...
    assert "Account deleted" not in "".join(surface.notes)  # ...but never actually visited
    assert surface.pages_visited == 5


async def test_crawl_skips_out_of_scope_external_link(mini_app_server, browser):
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    assert not any("example.com" in e.url for e in surface.endpoints)


async def test_crawl_collapses_numeric_ids_into_one_template(mini_app_server, browser):
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    user_endpoints = [e for e in surface.endpoints if e.path_template == "/users/{id}"]
    assert len(user_endpoints) == 1  # /users/42 and /users/7 collapse to one template
    assert not any(e.path_template in ("/users/42", "/users/7") for e in surface.endpoints)


async def test_crawl_records_form_without_submitting_it(mini_app_server, browser):
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    form_endpoints = [e for e in surface.endpoints if e.source == "form"]
    assert len(form_endpoints) == 1
    assert form_endpoints[0].method == "POST"
    assert form_endpoints[0].path_template == "/contact"


async def test_crawl_finds_js_only_endpoint_via_network_interception(mini_app_server, browser):
    """The whole point of not being a static-HTML-only crawler: an endpoint
    fetched by page JS but never linked anywhere is still discovered."""
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    network_endpoints = [e for e in surface.endpoints if e.source == "network"]
    assert any(e.path_template == "/api/hidden-admin-data" for e in network_endpoints)


async def test_crawl_respects_max_pages(mini_app_server, browser):
    crawler = _crawler(mini_app_server, max_pages=1)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    assert surface.pages_visited == 1


async def test_crawl_endpoints_tagged_with_persona_id(mini_app_server, browser):
    crawler = _crawler(mini_app_server)
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="admin-1")

    assert surface.persona_id == "admin-1"
    assert all(e.persona_id == "admin-1" for e in surface.endpoints)


async def test_crawl_follows_the_site_after_an_apex_to_www_redirect():
    """QA #37: target "abhyaasika.com", app on www.abhyaasika.com. The apex
    redirects to www; every link on the real site is on www. The crawl used
    to treat those as foreign and stop after one page."""
    import asyncio

    import uvicorn
    from playwright.async_api import async_playwright
    from starlette.applications import Starlette
    from starlette.responses import HTMLResponse, RedirectResponse
    from starlette.routing import Route

    from .conftest import _chromium_launch_kwargs, _free_port

    port = _free_port()

    async def any_page(request):
        if request.url.hostname == "abhyaasika.test":
            return RedirectResponse(f"http://www.abhyaasika.test:{port}{request.url.path}")
        links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(1, 4))
        return HTMLResponse(f"<html><body><h1>{request.url.path}</h1>{links}</body></html>")

    app = Starlette(routes=[Route("/{path:path}", any_page)])
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        async with async_playwright() as p:
            kwargs = _chromium_launch_kwargs()
            kwargs["args"] = [
                "--host-resolver-rules=MAP abhyaasika.test 127.0.0.1, "
                "MAP www.abhyaasika.test 127.0.0.1"
            ]
            browser = await p.chromium.launch(**kwargs)
            crawler = PersonaCrawler(
                scope_guard=ScopeGuard(
                    allowed_hosts={"abhyaasika.test", "*.abhyaasika.test"},
                    target_ownership_verified=True,
                ),
                rate_limiter=RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000),
                target_id="t",
            )
            surface = await crawler.crawl(
                browser, root_url=f"http://abhyaasika.test:{port}/", persona_id="anonymous"
            )
            await browser.close()
    finally:
        server.should_exit = True
        await task

    paths = {e.path_template for e in surface.endpoints}
    assert {"/p1", "/p2", "/p3"} <= paths, paths
    assert surface.pages_visited >= 4


async def test_one_dead_page_does_not_sink_the_rest_of_the_crawl(mini_app_server, browser):
    """Found in the QA round 3 run: after a page failed to load, the tab sat
    on a settling error page and every later goto was "interrupted by
    another navigation", so the crawl visited nothing."""
    from .conftest import _free_port

    dead_root = f"http://127.0.0.1:{_free_port()}/"  # nothing listens here
    surface = await _crawler(mini_app_server).crawl(
        browser, root_url=dead_root, persona_id="anonymous", seeds=[f"{mini_app_server}/"]
    )
    assert any("Failed to load" in n for n in surface.notes)
    assert surface.pages_visited >= 2, surface.notes


async def test_a_redirected_visit_is_recorded_where_it_ended(browser):
    """A logged-out visitor sent from /dashboard to /login reached /login, not
    /dashboard: recording the requested URL would claim the visitor reached
    logged-in content (the pages table said exactly that)."""
    import asyncio

    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import HTMLResponse, RedirectResponse
    from starlette.routing import Route

    from .conftest import _free_port

    async def dashboard(request):
        return RedirectResponse("/login", status_code=303)

    async def login(request):
        return HTMLResponse("<html><body>Sign in</body></html>")

    app = Starlette(routes=[Route("/dashboard", dashboard), Route("/login", login)])
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        crawler = PersonaCrawler(
            scope_guard=ScopeGuard(allowed_hosts={"127.0.0.1"}, target_ownership_verified=True),
            rate_limiter=RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000),
            target_id="t",
        )
        surface = await crawler.crawl(
            browser, root_url=f"http://127.0.0.1:{port}/dashboard", persona_id="anonymous"
        )
    finally:
        server.should_exit = True
        await task
    assert {e.path_template for e in surface.endpoints} == {"/login"}
    assert surface.pages_visited == 1


async def test_crawl_refuses_a_site_on_a_non_public_address(mini_app_server, browser):
    """The mini app listens on 127.0.0.1: with the address guard on, the crawl
    must not visit it, and says why instead of failing quietly."""
    from sentinel_core.address_guard import AddressGuard

    events: list[tuple[str, dict]] = []
    crawler = _crawler(
        mini_app_server,
        address_guard=AddressGuard(),
        on_event=lambda kind, persona, details: events.append((kind, details)),
    )
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")

    assert surface.pages_visited == 0
    assert surface.endpoints == []
    skips = [d for kind, d in events if kind == "skip"]
    assert skips and "non-public address" in skips[0]["reason"]
    assert any("non-public address" in n for n in surface.notes)


async def test_crawl_with_the_guard_off_still_works(mini_app_server, browser):
    from sentinel_core.address_guard import AddressGuard

    crawler = _crawler(mini_app_server, address_guard=AddressGuard(allow_private=True))
    surface = await crawler.crawl(browser, root_url=mini_app_server + "/", persona_id="alice")
    assert surface.pages_visited == 5


async def test_browser_requests_to_non_public_hosts_are_aborted_and_reported_once():
    from sentinel_core.address_guard import AddressGuard

    async def resolve(host):
        return ["10.0.0.9"] if host == "internal.acme.test" else ["93.184.216.34"]

    events: list[tuple[str, dict]] = []
    crawler = PersonaCrawler(
        scope_guard=ScopeGuard(allowed_hosts={"acme.test"}, target_ownership_verified=True),
        rate_limiter=RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000),
        target_id="t",
        address_guard=AddressGuard(resolver=resolve),
        on_event=lambda kind, persona, details: events.append((kind, details)),
    )

    class Ctx:
        handler = None

        async def route(self, pattern, handler):
            self.handler = handler

    class Route:
        def __init__(self):
            self.outcome = None

        async def fallback(self):
            self.outcome = "fallback"

        async def abort(self, reason):
            self.outcome = f"abort:{reason}"

    class Req:
        def __init__(self, url):
            self.url = url

    ctx = Ctx()
    await crawler._route_address_guard(ctx, "anonymous")

    async def go(url):
        route = Route()
        await ctx.handler(route, Req(url))
        return route.outcome

    assert await go("https://www.acme.test/app.js") == "fallback"
    assert await go("https://internal.acme.test/a") == "abort:blockedbyclient"
    assert await go("https://internal.acme.test/b") == "abort:blockedbyclient"
    assert len([e for e in events if e[0] == "skip"]) == 1  # reported once per host
