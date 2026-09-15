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
