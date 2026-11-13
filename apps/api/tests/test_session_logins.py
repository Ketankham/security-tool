"""v1 #1: cookie / header logins, "URL doesn't contain" success checks, and
the Test login endpoints (Celery mocked: the worker side is tested in
apps/worker/tests/test_login_engine.py)."""

from __future__ import annotations

import uuid

import pytest
from sentinel_db.enums import CredentialKind, LoginStrategy
from sentinel_db.models import Credential, Persona
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration

COOKIE_LOGIN = {
    "strategy": "cookie",
    "start_url": "https://app.sl.test/dashboard",
    "success_assertion": {"kind": "url_not_contains", "value": "/sign-in"},
}
HEADER_LOGIN = {**COOKIE_LOGIN, "strategy": "header", "header_name": "Authorization"}
FORM_LOGIN = {
    "start_url": "https://sl.test/sign-in",
    "steps": [
        {"action": "fill", "selector": "#email", "value": "a@sl.test"},
        {"action": "fill_secret", "selector": "#pw", "credential_ref": "password"},
        {"action": "click", "selector": "button"},
    ],
    "success_assertion": {"kind": "url_not_contains", "value": "/sign-in"},
}


async def _setup(client, slug):
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets", json={"root_domain": "sl.test", "display_name": "SL"}, headers=headers
        )
    ).json()
    return headers, target


async def _create(client, headers, target, recipe, secret, label="User"):
    return await client.post(
        f"/targets/{target['id']}/personas",
        json={
            "label": label,
            "role_name": "user",
            "login_recipe": recipe,
            "credential": {"kind": "password", "secret": secret},
        },
        headers=headers,
    )


async def _stored(db_engine, persona_id):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        persona = await session.get(Persona, uuid.UUID(persona_id))
        cred = await session.get(Credential, persona.credential_id)
        return persona, cred


async def test_cookie_login_is_saved_as_a_manual_session(client, db_engine):
    headers, target = await _setup(client, "cookie-ok")
    resp = await _create(client, headers, target, COOKIE_LOGIN, "Cookie: sid=abc; theme=dark")
    assert resp.status_code == 201, resp.text
    assert resp.json()["login_strategy"] == LoginStrategy.MANUAL_SESSION.value
    assert "abc" not in resp.text
    persona, cred = await _stored(db_engine, resp.json()["id"])
    assert cred.kind == CredentialKind.SESSION_IMPORT
    assert persona.login_recipe["strategy"] == "cookie"


async def test_header_login_is_saved_and_name_prefix_is_tolerated(client, db_engine):
    headers, target = await _setup(client, "header-ok")
    resp = await _create(client, headers, target, HEADER_LOGIN, "Authorization: Bearer tok123")
    assert resp.status_code == 201, resp.text
    assert resp.json()["login_strategy"] == LoginStrategy.API_TOKEN.value
    _, cred = await _stored(db_engine, resp.json()["id"])
    assert cred.kind == CredentialKind.API_TOKEN


async def test_form_login_accepts_url_not_contains(client):
    headers, target = await _setup(client, "form-notcontains")
    resp = await _create(client, headers, target, FORM_LOGIN, "pw")
    assert resp.status_code == 201, resp.text
    assert resp.json()["login_strategy"] == "form"


@pytest.mark.parametrize(
    ("recipe", "secret", "message"),
    [
        (COOKIE_LOGIN, "no-equals-sign", "not a name=value cookie"),
        (COOKIE_LOGIN, "sid=1\nX-Evil: 1", "single line"),
        (HEADER_LOGIN, "Bearer a\r\nX-Evil: 1", "single line"),
        ({**HEADER_LOGIN, "header_name": "Cookie"}, "x", "Use the cookie login"),
        ({**HEADER_LOGIN, "header_name": "Bad Header"}, "x", "not a valid header name"),
        ({**COOKIE_LOGIN, "steps": FORM_LOGIN["steps"]}, "sid=1", "has no steps"),
        ({**COOKIE_LOGIN, "allow_off_domain": True}, "sid=1", "allow_off_domain is not allowed"),
        (
            {**COOKIE_LOGIN, "start_url": "https://evil.example.org/"},
            "sid=1",
            "only ever sent to the target",
        ),
        ({**FORM_LOGIN, "steps": []}, "pw", "at least one step"),
    ],
)
async def test_bad_session_logins_are_rejected(client, recipe, secret, message):
    headers, target = await _setup(client, f"bad-{uuid.uuid4().hex[:8]}")
    resp = await _create(client, headers, target, recipe, secret)
    assert resp.status_code == 422, resp.text
    assert message in resp.text


async def test_cookie_login_without_a_value_is_rejected(client):
    headers, target = await _setup(client, "cookie-none")
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "U", "role_name": "u", "login_recipe": COOKIE_LOGIN},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "needs the cookie value" in resp.text


async def test_switching_strategy_requires_the_new_secret(client, db_engine):
    headers, target = await _setup(client, "switch")
    persona = (await _create(client, headers, target, FORM_LOGIN, "pw")).json()
    url = f"/targets/{target['id']}/personas/{persona['id']}"

    resp = await client.patch(url, json={"login_recipe": COOKIE_LOGIN}, headers=headers)
    assert resp.status_code == 422
    assert "needs the cookie value" in resp.text

    resp = await client.patch(
        url,
        json={"login_recipe": COOKIE_LOGIN, "credential": {"secret": "sid=xyz"}},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["login_strategy"] == LoginStrategy.MANUAL_SESSION.value
    _, cred = await _stored(db_engine, persona["id"])
    assert cred.kind == CredentialKind.SESSION_IMPORT

    # Replacing just the cookie checks it against the stored strategy.
    resp = await client.patch(url, json={"credential": {"secret": "garbage"}}, headers=headers)
    assert resp.status_code == 422
    assert "name=value" in resp.text


# --- Test login ------------------------------------------------------------------


@pytest.fixture
def fake_tests(monkeypatch):
    """Stands in for the broker + result backend."""
    results: dict[str, dict | None] = {}

    def dispatch(persona_id):
        test_id = str(uuid.uuid4())
        results[test_id] = None
        dispatch.last = (test_id, persona_id)
        return test_id

    monkeypatch.setattr("sentinel_api_app.routers.personas.dispatch_test_login", dispatch)
    monkeypatch.setattr(
        "sentinel_api_app.routers.personas.read_test_login", lambda tid: results.get(tid)
    )
    return results, dispatch


async def test_login_test_round_trip(client, fake_tests):
    results, dispatch = fake_tests
    headers, target = await _setup(client, "testlogin")
    persona = (await _create(client, headers, target, COOKIE_LOGIN, "sid=1")).json()
    base = f"/targets/{target['id']}/personas/{persona['id']}/test-login"

    started = await client.post(base, headers=headers)
    assert started.status_code == 202, started.text
    test_id = started.json()["test_id"]
    assert dispatch.last == (test_id, persona["id"])

    pending = (await client.get(f"{base}/{test_id}", headers=headers)).json()
    assert pending == {
        "status": "pending",
        "success": None,
        "error": None,
        "final_url": None,
        "screenshot_jpeg_b64": None,
        "duration_s": None,
        "checked_at": None,
    }

    results[test_id] = {
        "persona_id": persona["id"],
        "success": False,
        "error": "Success check failed: the URL still contained '/sign-in'",
        "final_url": "https://app.sl.test/sign-in",
        "screenshot_jpeg_b64": "AAAA",
        "duration_s": 3.2,
        "checked_at": "2026-11-13T10:00:00+00:00",
    }
    done = (await client.get(f"{base}/{test_id}", headers=headers)).json()
    assert done["status"] == "done" and done["success"] is False
    assert done["final_url"] == "https://app.sl.test/sign-in"
    assert done["screenshot_jpeg_b64"] == "AAAA"


async def test_login_test_needs_a_saved_login_and_is_org_scoped(client, fake_tests):
    results, _ = fake_tests
    headers, target = await _setup(client, "testlogin-scope")
    bare = (
        await client.post(
            f"/targets/{target['id']}/personas",
            json={"label": "Bare", "role_name": "b"},
            headers=headers,
        )
    ).json()
    resp = await client.post(
        f"/targets/{target['id']}/personas/{bare['id']}/test-login", headers=headers
    )
    assert resp.status_code == 409

    persona = (await _create(client, headers, target, COOKIE_LOGIN, "sid=1")).json()
    other_headers, other_target = await _setup(client, "testlogin-other")
    other = (await _create(client, other_headers, other_target, COOKIE_LOGIN, "sid=2")).json()

    # Org B can't start a test on org A's persona...
    resp = await client.post(
        f"/targets/{target['id']}/personas/{persona['id']}/test-login", headers=other_headers
    )
    assert resp.status_code == 404
    # ...nor read A's result through its own persona's URL.
    test_id = str(uuid.uuid4())
    results[test_id] = {"persona_id": persona["id"], "success": True}
    resp = await client.get(
        f"/targets/{other_target['id']}/personas/{other['id']}/test-login/{test_id}",
        headers=other_headers,
    )
    assert resp.status_code == 404


async def test_login_test_reports_an_unreachable_queue(client, monkeypatch):
    monkeypatch.setattr(
        "sentinel_api_app.routers.personas.dispatch_test_login", lambda persona_id: None
    )
    headers, target = await _setup(client, "testlogin-down")
    persona = (await _create(client, headers, target, COOKIE_LOGIN, "sid=1")).json()
    resp = await client.post(
        f"/targets/{target['id']}/personas/{persona['id']}/test-login", headers=headers
    )
    assert resp.status_code == 503
