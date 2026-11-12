"""Fixes from the QA bug log of 2026-11-12 (numbers refer to that log)."""

from __future__ import annotations

import uuid

import pytest
from sentinel_api_app.services.domains import normalize_root_domain

# --- #1 / #12 root domain normalisation (pure function, no DB) ---------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://www.abhyaasika.com", "www.abhyaasika.com"),
        ("https://www.abhyaasika.com/login?next=/", "www.abhyaasika.com"),
        ("  App.Example.COM.  ", "app.example.com"),
        ("example.com/some/path", "example.com"),
        ("http://example.com#frag", "example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
    ],
)
def test_root_domain_is_normalised(raw, expected):
    assert normalize_root_domain(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "enter a domain"),
        ("localhost", "full domain"),
        ("10.0.0.1", "not an IP"),
        ("https://[::1]/", "not an IP"),
        ("example.com:8443", "without a port"),
        ("https://user:pw@example.com", "without a username"),
        ("*.example.com", "wildcards"),
        ("exa mple.com", "valid domain"),
        ("-bad-.com", "valid domain"),
        ("a" * 64 + ".com", "valid domain"),
        (("a" * 60 + ".") * 5 + "com", "too long"),
        ("example.123", "valid domain"),
    ],
)
def test_bad_root_domains_are_rejected(raw, message):
    with pytest.raises(ValueError, match=message):
        normalize_root_domain(raw)


# --- API, real Postgres --------------------------------------------------------


async def _org(client, slug):
    resp = await client.post("/organizations", json={"name": slug, "slug": slug})
    assert resp.status_code == 201, resp.text
    return {"X-Org-Id": resp.json()["id"]}


async def _target(client, headers, domain="client.test"):
    resp = await client.post(
        "/targets", json={"root_domain": domain, "display_name": "Client"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_target_stores_bare_domain_and_challenge_uses_it(client):
    headers = await _org(client, "norm")
    target = await _target(client, headers, domain="https://www.Abhyaasika.com/login")
    assert target["root_domain"] == "www.abhyaasika.com"

    resp = await client.post(
        f"/targets/{target['id']}/ownership-challenge", json={"method": "dns_txt"}, headers=headers
    )
    assert "_sentinel-verify.www.abhyaasika.com" in resp.json()["instructions"]
    assert "https://" not in resp.json()["instructions"]


async def test_target_rejects_ip_with_readable_message(client):
    headers = await _org(client, "ipreject")
    resp = await client.post(
        "/targets", json={"root_domain": "127.0.0.1", "display_name": "x"}, headers=headers
    )
    assert resp.status_code == 422
    assert "not an IP address" in resp.text


# Change request: ownership gate switch


async def test_gate_on_by_default_blocks_unverified_scans(client, no_dispatch):
    headers = await _org(client, "gate-on")
    target = await _target(client, headers)
    assert target["ownership_check_required"] is True
    assert target["is_scannable"] is False
    resp = await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers)
    assert resp.status_code == 403


async def test_gate_off_makes_every_target_scannable(client, no_dispatch, monkeypatch):
    monkeypatch.setenv("REQUIRE_OWNERSHIP_VERIFICATION", "false")
    headers = await _org(client, "gate-off")
    target = await _target(client, headers)
    assert target["ownership_check_required"] is False
    assert target["is_scannable"] is True
    assert target["ownership_verified"] is False  # stored state is untouched

    listed = (await client.get("/targets", headers=headers)).json()
    assert listed[0]["is_scannable"] is True

    resp = await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers)
    assert resp.status_code == 201, resp.text


# #11 / #19 / #17 scope rules


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        ({"kind": "path_regex", "pattern": "(["}, "invalid regular expression"),
        ({"kind": "path_prefix", "pattern": "api/"}, "must start with '/'"),
        ({"kind": "method", "pattern": "FETCH"}, "unknown HTTP method"),
        ({"kind": "host", "pattern": "not a host"}, "invalid host pattern"),
    ],
)
async def test_invalid_scope_rules_are_rejected(client, rule, message):
    headers = await _org(client, f"sr-{uuid.uuid4().hex[:8]}")
    target = await _target(client, headers)
    resp = await client.post(
        f"/targets/{target['id']}/scope-rules", json={**rule, "effect": "exclude"}, headers=headers
    )
    assert resp.status_code == 422
    assert message in resp.text


async def test_scope_rules_normalise_dedupe_and_delete(client):
    headers = await _org(client, "sr-flow")
    target = await _target(client, headers)
    base = f"/targets/{target['id']}/scope-rules"

    method = await client.post(
        base, json={"kind": "method", "pattern": "delete", "effect": "exclude"}, headers=headers
    )
    assert method.status_code == 201 and method.json()["pattern"] == "DELETE"

    rule = {"kind": "path_regex", "pattern": r"^/payments?/", "effect": "exclude"}
    first = await client.post(base, json=rule, headers=headers)
    assert first.status_code == 201
    dup = await client.post(base, json=rule, headers=headers)
    assert dup.status_code == 409

    deleted = await client.delete(f"{base}/{first.json()['id']}", headers=headers)
    assert deleted.status_code == 204
    patterns = [r["pattern"] for r in (await client.get(base, headers=headers)).json()]
    assert patterns == ["DELETE"]

    # Another org can't delete it, and an unknown id is a 404.
    other = await _org(client, "sr-other")
    resp = await client.delete(f"{base}/{method.json()['id']}", headers=other)
    assert resp.status_code == 404
    resp = await client.delete(f"{base}/{uuid.uuid4()}", headers=headers)
    assert resp.status_code == 404


# #14 trust rank, #19 persona labels, #18 slugs


async def test_huge_trust_rank_is_a_422_not_a_500(client):
    headers = await _org(client, "trust")
    target = await _target(client, headers)
    resp = await client.post(
        f"/targets/{target['id']}/personas",
        json={"label": "Huge", "role_name": "x", "trust_rank": 99999999999999999999},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_duplicate_persona_label_is_rejected_case_insensitively(client):
    headers = await _org(client, "dup-persona")
    target = await _target(client, headers)
    url = f"/targets/{target['id']}/personas"
    assert (
        await client.post(url, json={"label": "Admin", "role_name": "admin"}, headers=headers)
    ).status_code == 201
    resp = await client.post(url, json={"label": " admin ", "role_name": "admin"}, headers=headers)
    assert resp.status_code == 409


@pytest.mark.parametrize("slug", ["Has Space", "UPPER", "a", "trailing-", "double--dash", "x" * 64])
async def test_bad_org_slugs_are_rejected(client, slug):
    resp = await client.post("/organizations", json={"name": "Name", "slug": slug})
    assert resp.status_code == 422


# QA #16 (API side): malformed ids were a 500 (asyncpg DataError), not a 4xx.


@pytest.mark.parametrize("path", ["/scans/abc", "/scans/abc/findings", "/scans/abc/report"])
async def test_malformed_scan_id_is_a_422_not_a_500(client, path):
    headers = await _org(client, f"badid-{uuid.uuid4().hex[:8]}")
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 422
