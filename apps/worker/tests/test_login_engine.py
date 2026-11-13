"""v1 #1 against a real browser and the real fixture app (fixtures/persona_app.py):

- cookie and header logins (the tester pasted a session);
- the "URL doesn't contain" check, including a page that only redirects to
  /login from JavaScript after it has loaded;
- failure results that say where the browser ended up, with a screenshot;
- a header login's token goes to the target's hosts only, never to another
  host the page loads from;
- the Test login job end to end (DB in, result dict out).
"""

from __future__ import annotations

import base64
import uuid

import httpx
from sentinel_auth import LoginRecipe, LoginReplayer, PersonaSession, SuccessAssertion
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_core.session_import import SESSION_HEADERS_KEY
from sentinel_db.enums import CredentialKind
from sentinel_db.models import Credential, Organization, Persona, Target
from sentinel_worker_app.scan_runner import _run_crawling
from sentinel_worker_app.test_login import run_test_login
from sqlalchemy.ext.asyncio import async_sessionmaker

MASTER_KEY = "pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="
NOT_ON_LOGIN = SuccessAssertion(kind="url_not_contains", value="/login", timeout_s=5)


async def _mint(server: str) -> str:
    async with httpx.AsyncClient() as client:
        return (await client.get(f"{server}/test/mint")).json()["token"]


def _recipe(server: str, path: str, strategy: str, **extra) -> LoginRecipe:
    return LoginRecipe(
        start_url=f"{server}{path}",
        steps=(),
        success_assertion=NOT_ON_LOGIN,
        strategy=strategy,
        **extra,
    )


async def test_cookie_login_works_and_keeps_the_session(browser, persona_app_server):
    token = await _mint(persona_app_server)
    result = await LoginReplayer(browser).replay(
        _recipe(persona_app_server, "/dashboard", "cookie"),
        session_secret=f"Cookie: session={token}; theme=dark",
        target_root_domain="127.0.0.1",
    )
    assert result.success, result.error
    assert result.final_url.endswith("/dashboard")
    cookies = {c["name"]: c["value"] for c in result.storage_state["cookies"]}
    assert cookies["session"] == token


async def test_dead_cookie_fails_with_where_it_ended_and_a_screenshot(browser, persona_app_server):
    result = await LoginReplayer(browser).replay(
        _recipe(persona_app_server, "/dashboard", "cookie"),
        session_secret="session=expired",
        target_root_domain="127.0.0.1",
        capture_screenshot=True,
    )
    assert not result.success
    assert "the URL still contained '/login'" in result.error
    assert result.final_url.endswith("/login")
    assert result.final_url in result.error
    assert result.screenshot[:2] == b"\xff\xd8"  # JPEG
    assert result.storage_state is None


async def test_url_check_waits_for_a_javascript_redirect(browser, persona_app_server):
    """/spa answers 200, then sends logged-out visitors to /login from JS.
    Passing the check in the instant before that redirect would let a dead
    session through."""
    result = await LoginReplayer(browser).replay(
        _recipe(persona_app_server, "/spa", "cookie"),
        session_secret="session=expired",
        target_root_domain="127.0.0.1",
    )
    assert not result.success
    assert result.final_url.endswith("/login")

    token = await _mint(persona_app_server)
    ok = await LoginReplayer(browser).replay(
        _recipe(persona_app_server, "/spa", "cookie"),
        session_secret=f"session={token}",
        target_root_domain="127.0.0.1",
    )
    assert ok.success, ok.error


async def test_header_login_never_sends_the_token_to_other_hosts(browser, persona_app_server):
    from sentinel_worker_test_fixture_persona_app import PIXEL_AUTH_SEEN  # loaded by conftest

    PIXEL_AUTH_SEEN.clear()
    token = await _mint(persona_app_server)
    result = await LoginReplayer(browser).replay(
        _recipe(persona_app_server, "/with-external", "header", header_name="Authorization"),
        session_secret=f"Authorization: Bearer {token}",
        target_root_domain="127.0.0.1",
    )
    assert result.success, result.error
    assert result.storage_state[SESSION_HEADERS_KEY] == {"Authorization": f"Bearer {token}"}
    # The page loaded an image from http://localhost:<port> — same server,
    # different host, so: not the target. It must not have seen the token.
    assert PIXEL_AUTH_SEEN == [None]

    # And the HTTP engine side carries it too.
    session = PersonaSession("p", result.storage_state, target_host="127.0.0.1")
    assert session.extra_headers() == {"Authorization": f"Bearer {token}"}


async def test_bad_pasted_values_fail_cleanly(browser, persona_app_server):
    replayer = LoginReplayer(browser)
    result = await replayer.replay(
        _recipe(persona_app_server, "/dashboard", "cookie"), session_secret="no-equals"
    )
    assert not result.success and "name=value" in result.error
    result = await replayer.replay(
        _recipe(persona_app_server, "/dashboard", "header", header_name="Authorization"),
        session_secret=None,
    )
    assert not result.success and "No header value is stored" in result.error


async def test_crawler_uses_a_header_session(browser, redis_client, persona_app_server):
    token = await _mint(persona_app_server)
    state = {
        "cookies": [],
        "origins": [],
        SESSION_HEADERS_KEY: {"Authorization": f"Bearer {token}"},
    }
    target = Target(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        root_domain="127.0.0.1",
        display_name="x",
        ownership_verified=True,
        authorization_accepted=True,
    )
    persona = Persona(id=uuid.uuid4(), target_id=target.id, label="H", role_name="h")
    surfaces = await _run_crawling(
        target=target,
        scope_rules=[],
        configured_personas=[persona],
        in_memory_sessions={str(persona.id): state},
        redis_client=redis_client,
        browser=browser,
        root_url=f"{persona_app_server}/",
    )
    by_persona = {s.persona_id: s for s in surfaces}
    authed_paths = {e.path_template for e in by_persona[str(persona.id)].endpoints}
    anon_paths = {e.path_template for e in by_persona["anonymous"].endpoints}
    assert "/settings" in authed_paths
    assert "/settings" not in anon_paths


async def test_run_test_login_end_to_end(db_engine, monkeypatch, persona_app_server):
    monkeypatch.setenv("KMS_MASTER_KEY", MASTER_KEY)
    token = await _mint(persona_app_server)
    crypto = EnvelopeCrypto(LocalMasterKeyProvider([MASTER_KEY.encode()]))
    data_key = crypto.generate_data_key()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        org = Organization(
            name="T",
            slug=f"t-{uuid.uuid4().hex[:8]}",
            wrapped_data_key=crypto.wrap_data_key(data_key),
        )
        session.add(org)
        await session.flush()
        target = Target(organization_id=org.id, root_domain="127.0.0.1", display_name="T")
        session.add(target)
        await session.flush()
        personas = []
        for label, secret in (("Good", f"session={token}"), ("Dead", "session=nope")):
            cred = Credential(
                kind=CredentialKind.SESSION_IMPORT,
                ciphertext=crypto.encrypt(data_key, secret.encode()),
            )
            session.add(cred)
            await session.flush()
            persona = Persona(
                target_id=target.id,
                label=label,
                role_name="u",
                credential_id=cred.id,
                login_recipe={
                    "strategy": "cookie",
                    "start_url": f"{persona_app_server}/dashboard",
                    "steps": [],
                    "success_assertion": {"kind": "url_not_contains", "value": "/login"},
                },
            )
            session.add(persona)
            personas.append(persona)
        await session.commit()

    good = await run_test_login(str(personas[0].id))
    assert good["success"] is True, good
    assert good["persona_id"] == str(personas[0].id)
    assert base64.b64decode(good["screenshot_jpeg_b64"])[:2] == b"\xff\xd8"

    dead = await run_test_login(str(personas[1].id))
    assert dead["success"] is False
    assert "Login replay failed" in dead["error"]
    assert dead["final_url"].endswith("/login")

    async with factory() as session:
        assert (await session.get(Persona, personas[0].id)).is_available is True
        row = await session.get(Persona, personas[1].id)
        assert row.is_available is False
        assert "still contained '/login'" in row.unavailable_reason

    missing = await run_test_login(str(uuid.uuid4()))
    assert missing["success"] is False and "no longer exists" in missing["error"]


class _UnreachableEngine:
    """An HttpEngine whose every request fails, like a target root URL that
    is down or refuses connections."""

    async def request(self, *args, **kwargs):
        raise ConnectionError("Request to https://down.test/ failed after 3 attempt(s)")


async def test_unreachable_session_probe_does_not_crash_the_login(browser, persona_app_server):
    """Regression (found in the v1 end-to-end run): the session-oracle probe
    raised ConnectionError for an unreachable root URL, which ended the whole
    scan as FAILED even though the login itself had worked."""
    from types import SimpleNamespace

    from sentinel_worker_app.auth_adapter import establish_persona

    token = await _mint(persona_app_server)

    class _PlainCrypto:
        def decrypt(self, key, ciphertext):
            return ciphertext

    persona = SimpleNamespace(
        id=uuid.uuid4(),
        login_recipe={
            "strategy": "cookie",
            "start_url": f"{persona_app_server}/dashboard",
            "steps": [],
            "success_assertion": {"kind": "url_not_contains", "value": "/login"},
        },
        credential=SimpleNamespace(ciphertext=f"session={token}".encode()),
    )
    result = await establish_persona(
        persona=persona,
        browser=browser,
        crypto=_PlainCrypto(),
        org_data_key=b"k",
        engine=_UnreachableEngine(),
        oracle_probe_url="https://down.test/",
        target_root_domain="127.0.0.1",
    )
    assert result.available is True
    assert result.session_oracle is None
    assert "couldn't check whether the session stays alive" in result.oracle_detail
