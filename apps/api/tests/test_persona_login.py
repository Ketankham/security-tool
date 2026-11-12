"""Persona login recipes: validation at save time, and setting/replacing a
login on an existing persona (PATCH). Real Postgres + real routes, like
test_flows.py."""

from __future__ import annotations

import uuid

import pytest
from sentinel_db.models import Credential, Persona
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration

# Exactly what the dashboard's simple login form produces.
UI_RECIPE = {
    "start_url": "https://lr.test/login",
    "steps": [
        {"action": "fill", "selector": "#email", "value": "member@lr.test"},
        {"action": "fill_secret", "selector": "#password", "credential_ref": "password"},
        {"action": "click", "selector": "button[type=submit]"},
    ],
    "success_assertion": {"kind": "url_contains", "value": "/dashboard"},
}
PASSWORD = {"kind": "password", "secret": "s3cret-pw"}


async def _org_and_target(client, slug: str, domain: str = "lr.test"):
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets", json={"root_domain": domain, "display_name": domain}, headers=headers
        )
    ).json()
    return headers, target


async def _persona(client, headers, target, **extra):
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "Member", "role_name": "member", **extra},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- validation at save time -------------------------------------------------


async def test_ui_recipe_is_accepted_and_sets_form_strategy(client):
    headers, target = await _org_and_target(client, "ui-recipe")
    body = await _persona(client, headers, target, login_recipe=UI_RECIPE, credential=PASSWORD)
    assert body["has_login_recipe"] is True
    assert body["login_strategy"] == "form"


async def test_recipe_without_password_is_rejected_on_create(client):
    headers, target = await _org_and_target(client, "no-pw")
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "M", "role_name": "m", "login_recipe": UI_RECIPE},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "needs a password" in resp.text


@pytest.mark.parametrize(
    ("bad_step", "message"),
    [
        ({"action": "fill", "selector": "#email"}, "needs: value"),
        ({"action": "click"}, "needs: selector"),
        ({"action": "goto"}, "needs: value"),
        ({"action": "fill", "selector": "#p", "value": "x", "credential_ref": "pw"}, "fill_secret"),
    ],
)
async def test_malformed_steps_are_rejected(client, bad_step, message):
    headers, target = await _org_and_target(client, f"bad-{uuid.uuid4().hex[:8]}")
    recipe = {**UI_RECIPE, "steps": [bad_step, *UI_RECIPE["steps"]]}
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "M", "role_name": "m", "login_recipe": recipe, "credential": PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 422
    assert message in resp.text


async def test_recipe_must_have_exactly_one_credential_ref(client):
    headers, target = await _org_and_target(client, "refs")
    no_secret = {**UI_RECIPE, "steps": [UI_RECIPE["steps"][0], UI_RECIPE["steps"][2]]}
    two_refs = {
        **UI_RECIPE,
        "steps": [
            *UI_RECIPE["steps"],
            {"action": "fill_secret", "selector": "#otp", "credential_ref": "other"},
        ],
    }
    for recipe, message in (
        (no_secret, "needs a 'fill_secret'"),
        (two_refs, "same credential_ref"),
    ):
        resp = await client.post(
            f"/targets/{target['id']}/personas",
            json={"label": "M", "role_name": "m", "login_recipe": recipe, "credential": PASSWORD},
            headers=headers,
        )
        assert resp.status_code == 422, recipe
        assert message in resp.text


# --- PATCH: set / replace a login on an existing persona ---------------------


async def test_patch_adds_login_to_a_persona_created_without_one(client):
    headers, target = await _org_and_target(client, "patch-add")
    persona = await _persona(client, headers, target)
    assert persona["has_login_recipe"] is False

    resp = await client.patch(
        f"/targets/{target['id']}/personas/{persona['id']}",
        json={"login_recipe": UI_RECIPE, "credential": PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["has_login_recipe"] is True
    assert body["login_strategy"] == "form"
    assert body["is_available"] is True
    assert "s3cret-pw" not in resp.text
    assert "#password" not in resp.text  # the recipe itself is never echoed


async def test_patch_recipe_alone_on_persona_without_password_is_rejected(client, db_engine):
    headers, target = await _org_and_target(client, "patch-nopw")
    persona = await _persona(client, headers, target)

    resp = await client.patch(
        f"/targets/{target['id']}/personas/{persona['id']}",
        json={"login_recipe": UI_RECIPE},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "no password" in resp.text

    # Nothing half-applied.
    listed = (await client.get(f"/targets/{target['id']}/personas", headers=headers)).json()
    assert listed[0]["has_login_recipe"] is False


async def test_patch_replacing_password_revokes_the_old_credential(client, db_engine):
    headers, target = await _org_and_target(client, "patch-rotate")
    persona = await _persona(client, headers, target, login_recipe=UI_RECIPE, credential=PASSWORD)

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        original = (await session.get(Persona, uuid.UUID(persona["id"]))).credential_id

    resp = await client.patch(
        f"/targets/{target['id']}/personas/{persona['id']}",
        json={"credential": {"kind": "password", "secret": "new-pw"}},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    async with factory() as session:
        row = await session.get(Persona, uuid.UUID(persona["id"]))
        assert row.credential_id != original
        creds = {c.id: c for c in (await session.execute(select(Credential))).scalars()}
        assert creds[original].revoked_at is not None
        assert creds[row.credential_id].revoked_at is None
        # The recipe was kept: only the password changed.
        assert row.login_recipe["start_url"] == UI_RECIPE["start_url"]


async def test_patch_clears_last_runs_unavailable_verdict(client, db_engine):
    headers, target = await _org_and_target(client, "patch-reset")
    persona = await _persona(client, headers, target, login_recipe=UI_RECIPE, credential=PASSWORD)

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        row = await session.get(Persona, uuid.UUID(persona["id"]))
        row.is_available = False
        row.unavailable_reason = "Success assertion failed: url_contains='/dashboard'"
        await session.commit()

    fixed = {**UI_RECIPE, "success_assertion": {"kind": "url_contains", "value": "/home"}}
    resp = await client.patch(
        f"/targets/{target['id']}/personas/{persona['id']}",
        json={"login_recipe": fixed},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_available"] is True
    assert resp.json()["unavailable_reason"] is None


async def test_patch_with_nothing_to_change_is_rejected(client):
    headers, target = await _org_and_target(client, "patch-empty")
    persona = await _persona(client, headers, target)
    resp = await client.patch(
        f"/targets/{target['id']}/personas/{persona['id']}", json={}, headers=headers
    )
    assert resp.status_code == 422


async def test_patch_cannot_reach_another_orgs_or_targets_persona(client):
    headers_a, target_a = await _org_and_target(client, "iso-a", domain="a.test")
    headers_b, target_b = await _org_and_target(client, "iso-b", domain="b.test")
    persona_a = await _persona(client, headers_a, target_a)
    body = {"login_recipe": UI_RECIPE, "credential": PASSWORD}

    # Org B, through org A's target id: the target lookup itself 404s.
    resp = await client.patch(
        f"/targets/{target_a['id']}/personas/{persona_a['id']}", json=body, headers=headers_b
    )
    assert resp.status_code == 404

    # Org B, through its *own* target id but org A's persona id.
    resp = await client.patch(
        f"/targets/{target_b['id']}/personas/{persona_a['id']}", json=body, headers=headers_b
    )
    assert resp.status_code == 404

    # Unknown persona id.
    resp = await client.patch(
        f"/targets/{target_a['id']}/personas/{uuid.uuid4()}", json=body, headers=headers_a
    )
    assert resp.status_code == 404


# --- QA #23: login URLs must be http(s) pages on the target -------------------


@pytest.mark.parametrize(
    ("start_url", "message"),
    [
        ("javascript:alert(1)", "must start with http"),
        ("https://evil.example.org/login", "not on lr.test"),
    ],
)
async def test_unsafe_login_url_is_rejected_on_create_and_patch(client, start_url, message):
    headers, target = await _org_and_target(client, f"unsafe-{uuid.uuid4().hex[:8]}")
    bad = {**UI_RECIPE, "start_url": start_url}
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "M", "role_name": "m", "login_recipe": bad, "credential": PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 422
    assert message in resp.text

    persona = await _persona(client, headers, target)
    resp = await client.patch(
        f"/targets/{target['id']}/personas/{persona['id']}",
        json={"login_recipe": bad, "credential": PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 422
    assert message in resp.text


async def test_off_domain_login_needs_explicit_confirmation(client):
    headers, target = await _org_and_target(client, "sso-confirm")
    sso = {**UI_RECIPE, "start_url": "https://login.microsoftonline.com/tenant/login"}
    url = f"/targets/{target['id']}/personas"
    body = {"label": "M", "role_name": "m", "credential": PASSWORD}
    assert (
        await client.post(url, json={**body, "login_recipe": sso}, headers=headers)
    ).status_code == 422
    resp = await client.post(
        url, json={**body, "login_recipe": {**sso, "allow_off_domain": True}}, headers=headers
    )
    assert resp.status_code == 201, resp.text


async def test_goto_step_off_target_is_rejected(client):
    headers, target = await _org_and_target(client, "goto-off")
    recipe = {
        **UI_RECIPE,
        "steps": [{"action": "goto", "value": "https://evil.example.org/"}, *UI_RECIPE["steps"]],
    }
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "M", "role_name": "m", "login_recipe": recipe, "credential": PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "step 1 (goto)" in resp.text


# --- QA #24: Edit login can load the saved recipe (never the password) --------


async def test_saved_login_can_be_read_back_without_the_password(client):
    headers, target = await _org_and_target(client, "readback")
    persona = await _persona(client, headers, target, login_recipe=UI_RECIPE, credential=PASSWORD)
    resp = await client.get(
        f"/targets/{target['id']}/personas/{persona['id']}/login", headers=headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["has_password"] is True
    assert body["login_recipe"]["start_url"] == UI_RECIPE["start_url"]
    assert body["login_recipe"]["steps"][0]["value"] == "member@lr.test"
    assert PASSWORD["secret"] not in resp.text

    bare = await _persona(client, headers, target, label="NoLogin")
    body = (
        await client.get(f"/targets/{target['id']}/personas/{bare['id']}/login", headers=headers)
    ).json()
    assert body == {"login_recipe": None, "has_password": False}

    other_headers, _ = await _org_and_target(client, "readback-other", domain="o.test")
    resp = await client.get(
        f"/targets/{target['id']}/personas/{persona['id']}/login", headers=other_headers
    )
    assert resp.status_code == 404
