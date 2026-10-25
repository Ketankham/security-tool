"""End-to-end flow through the control plane: org -> target -> ownership ->
authorization -> persona -> scan -> findings. Exercises the real routes,
real Postgres, real Pydantic validation — only the outbound DNS/HTTP calls
inside ownership verification and the Celery dispatch are stubbed.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


async def _create_org(client, slug="acme"):
    resp = await client.post("/organizations", json={"name": "Acme Inc", "slug": slug})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth_headers(org_id: str) -> dict[str, str]:
    return {"X-Org-Id": org_id}


async def test_health(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_missing_org_header_is_401(client):
    resp = await client.get("/targets")
    assert resp.status_code == 401


async def test_create_org_rejects_duplicate_slug(client):
    await _create_org(client, slug="dupe")
    resp = await client.post("/organizations", json={"name": "Dupe 2", "slug": "dupe"})
    assert resp.status_code == 409


async def test_target_is_scannable_on_creation(client):
    # Client-portal model: no in-app ownership gate — a target is scannable
    # as soon as it exists (authorization comes from the engagement).
    org = await _create_org(client, slug="lifecycle")
    headers = _auth_headers(org["id"])

    target_resp = await client.post(
        "/targets",
        json={"root_domain": "acme.test", "display_name": "Acme App"},
        headers=headers,
    )
    assert target_resp.status_code == 201
    assert target_resp.json()["is_scannable"] is True


async def test_ownership_endpoints_remain_available_but_do_not_gate(client):
    # The verification code is retained (dormant) for a future self-serve
    # tier; the endpoint still responds, but scannability no longer depends
    # on it.
    org = await _create_org(client, slug="dormantverify")
    headers = _auth_headers(org["id"])
    target = (
        await client.post(
            "/targets",
            json={"root_domain": "acme2.test", "display_name": "Acme 2"},
            headers=headers,
        )
    ).json()

    challenge_resp = await client.post(
        f"/targets/{target['id']}/ownership-challenge",
        json={"method": "dns_txt"},
        headers=headers,
    )
    assert challenge_resp.status_code == 200
    assert challenge_resp.json()["token"].startswith("sentinel-verify=")
    # Still scannable regardless of whether the challenge is ever satisfied.
    assert target["is_scannable"] is True


async def test_ownership_verify_without_challenge_is_400(client):
    org = await _create_org(client, slug="nochallenge")
    headers = _auth_headers(org["id"])
    target = (
        await client.post(
            "/targets", json={"root_domain": "x.test", "display_name": "X"}, headers=headers
        )
    ).json()

    resp = await client.post(f"/targets/{target['id']}/ownership-verify", headers=headers)
    assert resp.status_code == 400


async def test_scan_created_on_fresh_target(client, no_dispatch):
    # No gate: a scan can be created on a target as soon as it exists.
    org = await _create_org(client, slug="freshscan")
    headers = _auth_headers(org["id"])
    target = (
        await client.post(
            "/targets", json={"root_domain": "y.test", "display_name": "Y"}, headers=headers
        )
    ).json()

    resp = await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers)
    assert resp.status_code == 201


async def _make_scannable_target(client, headers, domain="scannable.test"):
    # No gate anymore: a freshly created target is already scannable.
    return (
        await client.post(
            "/targets", json={"root_domain": domain, "display_name": "Scannable"}, headers=headers
        )
    ).json()


async def test_scan_created_when_target_scannable(client, no_dispatch):
    org = await _create_org(client, slug="willscan")
    headers = _auth_headers(org["id"])
    target = await _make_scannable_target(client, headers)

    resp = await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers)
    assert resp.status_code == 201
    scan = resp.json()
    assert scan["state"] == "queued"
    assert scan["target_id"] == target["id"]

    get_resp = await client.get(f"/scans/{scan['id']}", headers=headers)
    assert get_resp.status_code == 200

    findings_resp = await client.get(f"/scans/{scan['id']}/findings", headers=headers)
    assert findings_resp.status_code == 200
    assert findings_resp.json() == []


async def test_persona_credential_is_never_returned(client):
    org = await _create_org(client, slug="personaorg")
    headers = _auth_headers(org["id"])
    target = (
        await client.post(
            "/targets", json={"root_domain": "p.test", "display_name": "P"}, headers=headers
        )
    ).json()

    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={
            "label": "Admin",
            "role_name": "admin",
            "trust_rank": 10,
            "credential": {"kind": "password", "secret": "hunter2"},
        },
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "credential" not in body
    assert "hunter2" not in resp.text
    assert body["trust_rank"] == 10
    assert body["has_login_recipe"] is False


async def test_persona_with_login_recipe_is_stored_but_never_echoed_back(client):
    org = await _create_org(client, slug="loginrecipeorg")
    headers = _auth_headers(org["id"])
    target = (
        await client.post(
            "/targets", json={"root_domain": "lr.test", "display_name": "LR"}, headers=headers
        )
    ).json()

    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={
            "label": "Member",
            "role_name": "member",
            "credential": {"kind": "password", "secret": "hunter2"},
            "login_recipe": {
                "start_url": "https://lr.test/login",
                "steps": [
                    {"action": "fill", "selector": "#u", "value": "alice"},
                    {"action": "fill_secret", "selector": "#p", "credential_ref": "pw"},
                    {"action": "click", "selector": "button"},
                ],
                "success_assertion": {"kind": "url_contains", "value": "/dashboard"},
            },
        },
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["has_login_recipe"] is True
    assert "login_recipe" not in body
    assert "start_url" not in resp.text


async def test_cross_org_cannot_read_another_orgs_target_or_scan(client, no_dispatch):
    org_a = await _create_org(client, slug="org-a")
    org_b = await _create_org(client, slug="org-b")
    headers_a = _auth_headers(org_a["id"])
    headers_b = _auth_headers(org_b["id"])

    target = await _make_scannable_target(client, headers_a, domain="isolated.test")
    scan = (await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers_a)).json()

    # org B must not be able to read org A's target...
    resp = await client.get(f"/targets/{target['id']}", headers=headers_b)
    assert resp.status_code == 404

    # ...nor its scan...
    resp = await client.get(f"/scans/{scan['id']}", headers=headers_b)
    assert resp.status_code == 404

    # ...nor its findings.
    resp = await client.get(f"/scans/{scan['id']}/findings", headers=headers_b)
    assert resp.status_code == 404


async def test_unknown_org_header_is_404(client):
    resp = await client.get(
        "/targets", headers={"X-Org-Id": "00000000-0000-0000-0000-000000000000"}
    )
    assert resp.status_code == 404


async def test_malformed_org_header_is_400(client):
    resp = await client.get("/targets", headers={"X-Org-Id": "not-a-uuid"})
    assert resp.status_code == 400
