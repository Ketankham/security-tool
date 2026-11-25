"""Who is calling: the proxy secret, header spoofing, startup guards.

The API is reachable from other containers, so a bare X-Sentinel-User header
proves nothing; it is believed only together with the shared proxy secret.
These tests build the real app and drive it over ASGI (no database needed).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sentinel_api_app.config import Settings
from sentinel_api_app.identity import USERNAME_RE, resolve_identity
from sentinel_api_app.main import NOT_SIGNED_IN, create_app
from starlette.requests import Request

SECRET = "proxy-secret-for-tests"
GOOD = {"X-Sentinel-Proxy-Secret": SECRET, "X-Sentinel-User": "alice"}


@pytest.fixture
def identity_env(monkeypatch):
    for name in ("REQUIRE_IDENTITY", "SENTINEL_PROXY_SECRET", "DEV_IDENTITY", "ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REQUIRE_IDENTITY", "true")
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", SECRET)
    return monkeypatch


async def _client():
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


# --- identity required ---------------------------------------------------------


async def test_no_headers_is_401_with_a_helpful_message(identity_env):
    async with await _client() as client:
        for path in ("/whoami", "/targets", "/scan-estimate"):
            resp = await client.get(path)
            assert resp.status_code == 401, path
            assert resp.json() == {"detail": NOT_SIGNED_IN}
    assert NOT_SIGNED_IN == (
        "Not signed in. Open Sentinel through its sign-in page (/security); requests "
        "that bypass the sign-in proxy are refused."
    )


async def test_writes_are_refused_too(identity_env):
    async with await _client() as client:
        assert (
            await client.post("/organizations", json={"name": "x", "slug": "x"})
        ).status_code == 401


async def test_healthz_needs_no_identity(identity_env):
    async with await _client() as client:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        # ...but only exactly that path
        assert (await client.get("/healthz/extra")).status_code == 401
        assert (await client.get("/healthz/../whoami")).status_code == 401


async def test_user_header_without_the_secret_is_ignored(identity_env):
    async with await _client() as client:
        resp = await client.get("/whoami", headers={"X-Sentinel-User": "alice"})
        assert resp.status_code == 401


async def test_user_header_with_the_wrong_secret_is_ignored(identity_env):
    async with await _client() as client:
        for secret in ("wrong", "", SECRET + "x", SECRET[:-1], SECRET.upper()):
            resp = await client.get(
                "/whoami", headers={"X-Sentinel-User": "alice", "X-Sentinel-Proxy-Secret": secret}
            )
            assert resp.status_code == 401, secret


async def test_non_ascii_secret_is_a_clean_refusal_not_an_error(identity_env):
    async with await _client() as client:
        resp = await client.get(
            "/whoami",
            headers=[(b"x-sentinel-user", b"alice"), (b"x-sentinel-proxy-secret", b"caf\xe9")],
        )
        assert resp.status_code == 401


async def test_secret_alone_without_a_user_is_not_an_identity(identity_env):
    async with await _client() as client:
        resp = await client.get("/whoami", headers={"X-Sentinel-Proxy-Secret": SECRET})
        assert resp.status_code == 401


async def test_the_right_secret_gives_the_identity(identity_env):
    async with await _client() as client:
        resp = await client.get("/whoami", headers=GOOD)
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "alice"
        assert body["source"] == "proxy"


async def test_header_names_are_case_insensitive(identity_env):
    async with await _client() as client:
        resp = await client.get(
            "/whoami",
            headers={"x-SENTINEL-user": "alice", "X-SENTINEL-PROXY-SECRET": SECRET},
        )
        assert resp.json()["username"] == "alice"


@pytest.mark.parametrize(
    "bad",
    [
        "a b",
        "A",  # upper case
        "Alice",
        "-alice",  # must start with a letter or digit
        ".alice",
        "alice!",
        "ali/ce",
        "a" * 33,
        "a" * 65,
        "aé",
    ],
)
async def test_invalid_usernames_are_rejected_even_with_the_right_secret(identity_env, bad):
    async with await _client() as client:
        resp = await client.get(
            "/whoami",
            headers={"X-Sentinel-Proxy-Secret": SECRET, "X-Sentinel-User": bad.encode()},
        )
        assert resp.status_code == 401, bad


@pytest.mark.parametrize("good", ["a", "alice", "a.b-c_d", "0day", "a" * 32])
async def test_valid_usernames_are_accepted(identity_env, good):
    async with await _client() as client:
        resp = await client.get(
            "/whoami", headers={"X-Sentinel-Proxy-Secret": SECRET, "X-Sentinel-User": good}
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == good


def test_username_pattern_matches_the_user_management_script():
    assert USERNAME_RE.pattern == r"^[a-z0-9][a-z0-9._-]{0,31}$"
    assert USERNAME_RE.fullmatch("a\n") is None  # no trailing newline sneaks through


async def test_dev_identity_is_ignored_in_production_by_resolve(identity_env):
    """create_app refuses this configuration outright; resolve_identity must
    also never honour it, whatever builds the settings."""
    settings = Settings(environment="production", dev_identity="demo", proxy_shared_secret=SECRET)
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 5)})
    assert resolve_identity(request, settings) is None


async def test_a_forwarded_for_header_gives_the_client_address_only_via_the_proxy():
    settings = Settings(proxy_shared_secret=SECRET)

    def make(headers: dict[str, str]) -> Request:
        return Request(
            {
                "type": "http",
                "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
                "client": ("10.0.0.9", 5),
            }
        )

    ident = resolve_identity(
        make({**GOOD, "X-Forwarded-For": "203.0.113.7, 10.1.1.1", "User-Agent": "UA/1"}), settings
    )
    assert ident is not None
    assert ident.client_ip == "203.0.113.7"
    assert ident.user_agent == "UA/1"
    assert ident.source == "proxy"
    # without a forwarded header, the socket peer
    ident = resolve_identity(make(GOOD), settings)
    assert ident is not None and ident.client_ip == "10.0.0.9"
    # lengths are bounded so a header cannot overflow the audit columns
    ident = resolve_identity(
        make({**GOOD, "X-Forwarded-For": "9" * 500, "User-Agent": "u" * 900}), settings
    )
    assert ident is not None
    assert len(ident.client_ip or "") <= 64
    assert len(ident.user_agent or "") <= 300


# --- startup guards ------------------------------------------------------------


def test_startup_fails_when_identity_is_required_but_no_secret_is_set(monkeypatch):
    monkeypatch.setenv("REQUIRE_IDENTITY", "true")
    monkeypatch.delenv("SENTINEL_PROXY_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="SENTINEL_PROXY_SECRET"):
        create_app()


def test_startup_fails_with_a_dev_identity_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEV_IDENTITY", "demo")
    with pytest.raises(RuntimeError, match="DEV_IDENTITY"):
        create_app()


def test_startup_fails_with_an_invalid_dev_identity(monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("DEV_IDENTITY", "Not Valid")
    with pytest.raises(RuntimeError, match="DEV_IDENTITY"):
        create_app()


def test_startup_is_fine_with_the_secret_set_and_in_default_dev_mode(monkeypatch):
    monkeypatch.setenv("REQUIRE_IDENTITY", "true")
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", "x")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("DEV_IDENTITY", raising=False)
    assert create_app() is not None


# --- identity not required (local development, tests) --------------------------


async def test_without_require_identity_requests_pass_and_whoami_says_nobody(monkeypatch):
    for name in ("REQUIRE_IDENTITY", "SENTINEL_PROXY_SECRET", "DEV_IDENTITY", "ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    async with await _client() as client:
        body = (await client.get("/whoami")).json()
        assert body["username"] is None
        assert body["source"] is None


async def test_a_spoofed_header_is_still_nobody_when_identity_is_not_required(monkeypatch):
    for name in ("REQUIRE_IDENTITY", "DEV_IDENTITY", "ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", SECRET)
    async with await _client() as client:
        resp = await client.get("/whoami", headers={"X-Sentinel-User": "evil"})
        assert resp.status_code == 200
        assert resp.json()["username"] is None


async def test_dev_identity_stands_in_for_the_proxy_outside_production(monkeypatch):
    for name in ("REQUIRE_IDENTITY", "SENTINEL_PROXY_SECRET", "ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DEV_IDENTITY", "demo")
    async with await _client() as client:
        body = (await client.get("/whoami")).json()
        assert body["username"] == "demo"
        assert body["source"] == "dev"


async def test_dev_identity_satisfies_require_identity_locally(monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("REQUIRE_IDENTITY", "true")
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", SECRET)
    monkeypatch.setenv("DEV_IDENTITY", "demo")
    async with await _client() as client:
        assert (await client.get("/whoami")).json()["username"] == "demo"


async def test_a_proxy_identity_wins_over_a_dev_identity(monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", SECRET)
    monkeypatch.setenv("DEV_IDENTITY", "demo")
    async with await _client() as client:
        body = (await client.get("/whoami", headers=GOOD)).json()
        assert body["username"] == "alice"
        assert body["source"] == "proxy"


async def test_a_bad_username_does_not_fall_back_to_the_dev_identity(monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", SECRET)
    monkeypatch.setenv("DEV_IDENTITY", "demo")
    async with await _client() as client:
        body = (
            await client.get(
                "/whoami",
                headers={"X-Sentinel-Proxy-Secret": SECRET, "X-Sentinel-User": "bad name"},
            )
        ).json()
        assert body["username"] is None


async def test_the_proxy_secret_is_read_from_sentinel_proxy_secret(monkeypatch):
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", "from-env")
    assert Settings().proxy_shared_secret == "from-env"


# --- /whoami contents and /scan-estimate ---------------------------------------


async def test_whoami_reports_the_available_tools_and_the_statement(identity_env):
    async with await _client() as client:
        body = (await client.get("/whoami", headers=GOOD)).json()
    assert body["available_tools"] == ["dir_bruteforce", "port_scan", "all_ports"]
    assert body["statement"]["version"] == "1"
    assert "{client}" in body["statement"]["template"]
    assert "{target}" in body["statement"]["template"]
    assert "{target}" in body["statement"]["all_ports_template"]


async def test_whoami_lists_implemented_tools(identity_env, monkeypatch):
    monkeypatch.setattr(
        "sentinel_core.scan_options.IMPLEMENTED_ACTIVE_TOOLS",
        ("dir_bruteforce", "port_scan"),
    )
    async with await _client() as client:
        assert (await client.get("/whoami", headers=GOOD)).json()["available_tools"] == [
            "dir_bruteforce",
            "port_scan",
        ]


async def test_scan_estimate_mirrors_the_scan_options(identity_env):
    async with await _client() as client:
        resp = await client.get(
            "/scan-estimate",
            params={"dir_bruteforce": "true", "speed": "normal", "recon_profile": "light"},
            headers=GOOD,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["dir_bruteforce"]["seconds_per_host"] == 300
        assert body["port_scan"] is None
        assert body["total_seconds"] == body["dir_bruteforce"]["seconds_total"]

        empty = (await client.get("/scan-estimate", headers=GOOD)).json()
        assert empty["total_seconds"] == 0

        assert (
            await client.get("/scan-estimate", params={"speed": "warp"}, headers=GOOD)
        ).status_code == 422
        assert (
            await client.get("/scan-estimate", params={"wordlist": "huge"}, headers=GOOD)
        ).status_code == 422
