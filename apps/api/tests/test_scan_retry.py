"""v1 #2: failed scans can be retried, and a scan the queue never received
is failed straight away instead of sitting "Queued" forever."""

from __future__ import annotations

import uuid

import pytest
from sentinel_core.state_machine import ScanState
from sentinel_db.models import Scan
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration


async def _scan(client, slug, monkeypatch):
    monkeypatch.setenv("REQUIRE_OWNERSHIP_VERIFICATION", "false")
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets", json={"root_domain": f"{slug}.test", "display_name": "x"}, headers=headers
        )
    ).json()
    scan = (await client.post(f"/targets/{target['id']}/scans", json={}, headers=headers)).json()
    return headers, target, scan


async def _set_state(db_engine, scan_id, state):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        row = await session.get(Scan, uuid.UUID(scan_id))
        row.state = state
        await session.commit()


async def test_retry_starts_a_fresh_scan_of_the_same_target(
    client, db_engine, no_dispatch, monkeypatch
):
    headers, target, scan = await _scan(client, "retry-ok", monkeypatch)
    await _set_state(db_engine, scan["id"], ScanState.FAILED)

    resp = await client.post(f"/scans/{scan['id']}/retry", headers=headers)
    assert resp.status_code == 201, resp.text
    new = resp.json()
    assert new["id"] != scan["id"]
    assert new["target_id"] == target["id"]
    assert new["state"] == "queued"
    assert new["triggered_by"] == "retry"

    # The old scan is history, untouched.
    old = (await client.get(f"/scans/{scan['id']}", headers=headers)).json()
    assert old["state"] == "failed"


async def test_running_scan_cannot_be_retried(client, db_engine, no_dispatch, monkeypatch):
    headers, _, scan = await _scan(client, "retry-busy", monkeypatch)
    await _set_state(db_engine, scan["id"], ScanState.CRAWLING)
    resp = await client.post(f"/scans/{scan['id']}/retry", headers=headers)
    assert resp.status_code == 409


async def test_retry_is_scoped_to_the_callers_org(client, db_engine, no_dispatch, monkeypatch):
    _, _, scan = await _scan(client, "retry-a", monkeypatch)
    other_headers, _, _ = await _scan(client, "retry-b", monkeypatch)
    await _set_state(db_engine, scan["id"], ScanState.FAILED)
    resp = await client.post(f"/scans/{scan['id']}/retry", headers=other_headers)
    assert resp.status_code == 404


async def test_scan_is_failed_at_once_when_the_queue_is_unreachable(client, monkeypatch):
    monkeypatch.setattr("sentinel_api_app.routers.scans.dispatch_scan", lambda scan_id: False)
    _, _, scan = await _scan(client, "no-queue", monkeypatch)
    assert scan["state"] == "failed"
    assert "job queue" in scan["fail_reason"]
    assert scan["finished_at"] is not None
