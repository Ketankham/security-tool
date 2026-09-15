"""End-to-end flow through the control plane: org -> target -> ownership ->
authorization -> persona -> scan -> findings. Exercises the real routes,
real Postgres, real Pydantic validation — only the outbound DNS/HTTP calls
inside ownership verification and the Celery dispatch are stubbed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sentinel_api_app.services.ownership import VerificationResult

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


async def test_full_target_lifecycle_to_scannable(client):
    org = await _create_org(client, slug="lifecycle")
    headers = _auth_headers(org["id"])

    target_resp = await client.post(
        "/targets",
        json={"root_domain": "acme.test", "display_name": "Acme App"},
        headers=headers,
    )
    assert target_resp.status_code == 201
    target = target_resp.json()
    assert target["is_scannable"] is False

    challenge_resp = await client.post(
        f"/targets/{target['id']}/ownership-challenge",
        json={"method": "dns_txt"},
        headers=headers,
    )
    assert challenge_resp.status_code == 200
    challenge = challenge_resp.json()
    assert challenge["token"].startswith("sentinel-verify=")

    with patch(
        "sentinel_api_app.routers.targets.verify_ownership",
        new=AsyncMock(return_value=VerificationResult(True, "matched (test double)")),
    ):
        verify_resp = await client.post(
            f"/targets/{target['id']}/ownership-verify", headers=headers
        )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["verified"] is True

    target_resp = await client.get(f"/targets/{target['id']}", headers=headers)
    target = target_resp.json()
    assert target["ownership_verified"] is True
    assert target["is_scannable"] is False  # authorization not yet accepted

    auth_resp = await client.post(
        f"/targets/{target['id']}/authorization", json={"accepted": True}, headers=headers
    )
    assert auth_resp.status_code == 200
    assert auth_resp.json()["is_scannable"] is True


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


async def test_scan_requires_scannable_target(client, no_dispatch):
    org = await _create_org(client, slug="notscannable")
    headers = _auth_headers(org["id"])
    target = (
        await client.post(
            "/targets", json={"root_domain": "y.test", "display_name": "Y"}, headers=headers
        )
    ).json()

    resp = await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers)
    assert resp.status_code == 403


async def _make_scannable_target(client, headers, domain="scannable.test"):
    target = (
        await client.post(
            "/targets", json={"root_domain": domain, "display_name": "Scannable"}, headers=headers
        )
    ).json()
    await client.post(
        f"/targets/{target['id']}/ownership-challenge", json={"method": "dns_txt"}, headers=headers
    )
    with patch(
        "sentinel_api_app.routers.targets.verify_ownership",
        new=AsyncMock(return_value=VerificationResult(True, "matched (test double)")),
    ):
        await client.post(f"/targets/{target['id']}/ownership-verify", headers=headers)
    await client.post(
        f"/targets/{target['id']}/authorization", json={"accepted": True}, headers=headers
    )
    return target


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
