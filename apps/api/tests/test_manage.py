"""Editing and deleting organizations, targets and personas (QA #40 and the
"can't edit or delete" follow-ups), and Run scan speed/depth."""

from __future__ import annotations

import uuid

import pytest
from sentinel_core.state_machine import ScanState
from sentinel_db.models import Credential, Organization, Persona, Scan, Target, TranscriptRecord
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration

RECIPE = {
    "strategy": "cookie",
    "start_url": "https://www.m.test/dashboard",
    "success_assertion": {"kind": "url_not_contains", "value": "/login"},
}


async def _setup(client, slug):
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets", json={"root_domain": "m.test", "display_name": "M"}, headers=headers
        )
    ).json()
    persona = (
        await client.post(
            f"/targets/{target['id']}/personas",
            json={
                "label": "Teacher",
                "role_name": "teacher",
                "login_recipe": RECIPE,
                "credential": {"secret": "sid=1"},
            },
            headers=headers,
        )
    ).json()
    return org, headers, target, persona


async def _add_scan_with_transcript(db_engine, target_id, persona_id, state=ScanState.COMPLETE):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = Scan(target_id=uuid.UUID(target_id), state=state)
        session.add(scan)
        await session.flush()
        session.add(
            TranscriptRecord(
                transcript_id=uuid.uuid4().hex,
                scan_id=scan.id,
                persona_id=uuid.UUID(persona_id),
                method="GET",
                url="https://www.m.test/",
                status_code=200,
            )
        )
        await session.commit()
        return scan.id


async def _count(db_engine, model):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        return (await session.execute(select(func.count()).select_from(model))).scalar_one()


async def test_delete_persona_keeps_old_scans_and_removes_its_secret(client, db_engine):
    _, headers, target, persona = await _setup(client, "del-persona")
    scan_id = await _add_scan_with_transcript(db_engine, target["id"], persona["id"])
    creds_before = await _count(db_engine, Credential)

    resp = await client.delete(f"/targets/{target['id']}/personas/{persona['id']}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert (await client.get(f"/targets/{target['id']}/personas", headers=headers)).json() == []
    assert await _count(db_engine, Credential) == creds_before - 1
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        transcript = (
            await session.execute(
                select(TranscriptRecord).where(TranscriptRecord.scan_id == scan_id)
            )
        ).scalar_one()
        assert transcript.persona_id is None


async def test_delete_is_refused_while_a_scan_runs(client, db_engine):
    _, headers, target, persona = await _setup(client, "del-running")
    await _add_scan_with_transcript(db_engine, target["id"], persona["id"], ScanState.CRAWLING)
    for url in (
        f"/targets/{target['id']}/personas/{persona['id']}",
        f"/targets/{target['id']}",
    ):
        resp = await client.delete(url, headers=headers)
        assert resp.status_code == 409, url
        assert "still running" in resp.text


async def test_delete_target_and_organization(client, db_engine):
    org, headers, target, persona = await _setup(client, "del-org")
    await _add_scan_with_transcript(db_engine, target["id"], persona["id"])
    second = (
        await client.post(
            "/targets", json={"root_domain": "n.test", "display_name": "N"}, headers=headers
        )
    ).json()

    assert (await client.delete(f"/targets/{second['id']}", headers=headers)).status_code == 204
    assert [t["id"] for t in (await client.get("/targets", headers=headers)).json()] == [
        target["id"]
    ]

    creds_before = await _count(db_engine, Credential)
    assert (await client.delete(f"/organizations/{org['id']}")).status_code == 204
    assert org["id"] not in {o["id"] for o in (await client.get("/organizations")).json()}
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        assert await session.get(Organization, uuid.UUID(org["id"])) is None
        assert await session.get(Target, uuid.UUID(target["id"])) is None
        assert await session.get(Persona, uuid.UUID(persona["id"])) is None
    assert await _count(db_engine, Credential) == creds_before - 1
    assert (await client.delete(f"/organizations/{org['id']}")).status_code == 404


async def test_targets_and_personas_are_scoped_to_their_org(client):
    _, headers, target, persona = await _setup(client, "scope-a")
    _, other, _, _ = await _setup(client, "scope-b")
    assert (await client.delete(f"/targets/{target['id']}", headers=other)).status_code == 404
    resp = await client.delete(f"/targets/{target['id']}/personas/{persona['id']}", headers=other)
    assert resp.status_code == 404
    resp = await client.patch(f"/targets/{target['id']}", json={"display_name": "x"}, headers=other)
    assert resp.status_code == 404


async def test_edit_target_domain_and_name(client):
    _, headers, target, _ = await _setup(client, "edit-target")
    resp = await client.patch(
        f"/targets/{target['id']}",
        json={"root_domain": "https://www.M.test/login", "display_name": "M (www)"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["root_domain"] == "www.m.test"
    assert resp.json()["display_name"] == "M (www)"
    bad = await client.patch(
        f"/targets/{target['id']}", json={"root_domain": "10.0.0.1"}, headers=headers
    )
    assert bad.status_code == 422


async def test_edit_persona_details_keeps_the_login(client):
    _, headers, target, persona = await _setup(client, "edit-persona")
    base = f"/targets/{target['id']}/personas"
    await client.post(base, json={"label": "Student", "role_name": "s"}, headers=headers)

    resp = await client.patch(
        f"{base}/{persona['id']}",
        json={"label": "Head teacher", "trust_rank": 40, "tenant_key": "school-a"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["label"], body["trust_rank"], body["tenant_key"]) == (
        "Head teacher",
        40,
        "school-a",
    )
    assert body["has_login_recipe"] is True

    clash = await client.patch(
        f"{base}/{persona['id']}", json={"label": "student"}, headers=headers
    )
    assert clash.status_code == 409


async def test_scan_speed_and_depth_are_stored_and_reused_by_retry(
    client, db_engine, no_dispatch, monkeypatch
):
    monkeypatch.setenv("REQUIRE_OWNERSHIP_VERIFICATION", "false")
    _, headers, target, _ = await _setup(client, "scan-opts")
    resp = await client.post(
        f"/targets/{target['id']}/scans", json={"speed": "gentle", "depth": "deep"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["options"] == {"speed": "gentle", "depth": "deep"}

    bad = await client.post(
        f"/targets/{target['id']}/scans", json={"speed": "ludicrous"}, headers=headers
    )
    assert bad.status_code == 422

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        row = await session.get(Scan, uuid.UUID(scan["id"]))
        row.state = ScanState.FAILED
        await session.commit()
    retried = (await client.post(f"/scans/{scan['id']}/retry", headers=headers)).json()
    assert retried["options"] == {"speed": "gentle", "depth": "deep"}
