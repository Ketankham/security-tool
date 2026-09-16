"""POST /quick-scan and GET /scans/{id}/report. Celery dispatch is mocked
(same convention as test_flows.py), so these tests exercise routing, the
enable_quick_scan gate, org/target auto-provisioning and reuse, and the
report read path — not the worker's actual report generation, which
apps/worker/tests/test_scan_runner.py already covers against a real
pipeline.
"""

from __future__ import annotations

import json

import pytest
from sentinel_db.enums import ReportFormat
from sentinel_db.models import Report

pytestmark = pytest.mark.integration


@pytest.fixture
def no_quick_scan_dispatch(monkeypatch):
    monkeypatch.setattr("sentinel_api_app.routers.quick_scan.dispatch_scan", lambda scan_id: False)


@pytest.fixture
def quick_scan_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_QUICK_SCAN", "true")


async def test_quick_scan_disabled_by_default(client, no_quick_scan_dispatch):
    resp = await client.post("/quick-scan", json={"url": "https://example.com"})
    assert resp.status_code == 403


async def test_quick_scan_creates_scannable_target_without_org_header(
    client, no_quick_scan_dispatch, quick_scan_enabled
):
    resp = await client.post("/quick-scan", json={"url": "https://example.com/some/path"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["root_domain"] == "example.com"
    assert body["state"] == "queued"

    # The returned org_id lets the caller use the normal authenticated
    # endpoints from here on — quick-scan skips onboarding, not read auth.
    headers = {"X-Org-Id": body["org_id"]}
    target_resp = await client.get(f"/targets/{body['target_id']}", headers=headers)
    assert target_resp.status_code == 200
    assert target_resp.json()["is_scannable"] is True


async def test_quick_scan_accepts_a_bare_domain(client, no_quick_scan_dispatch, quick_scan_enabled):
    resp = await client.post("/quick-scan", json={"url": "example.com"})
    assert resp.status_code == 201
    assert resp.json()["root_domain"] == "example.com"


async def test_quick_scan_reuses_org_and_target_for_the_same_domain(
    client, no_quick_scan_dispatch, quick_scan_enabled
):
    first = (await client.post("/quick-scan", json={"url": "https://reused.test"})).json()
    second = (await client.post("/quick-scan", json={"url": "https://reused.test/other"})).json()

    assert first["org_id"] == second["org_id"]
    assert first["target_id"] == second["target_id"]
    assert first["scan_id"] != second["scan_id"]  # a new scan every call


async def test_quick_scan_rejects_unparseable_url(
    client, no_quick_scan_dispatch, quick_scan_enabled
):
    resp = await client.post("/quick-scan", json={"url": "://not-a-url"})
    assert resp.status_code == 400


async def test_report_404_before_generation(client, no_quick_scan_dispatch, quick_scan_enabled):
    body = (await client.post("/quick-scan", json={"url": "https://noreport.test"})).json()
    headers = {"X-Org-Id": body["org_id"]}

    resp = await client.get(f"/scans/{body['scan_id']}/report", headers=headers)
    assert resp.status_code == 404


async def test_report_returns_stored_content_when_present(
    client, no_quick_scan_dispatch, quick_scan_enabled, db_engine, tmp_path, monkeypatch
):
    from sentinel_core.transcript import LocalTranscriptStore
    from sqlalchemy.ext.asyncio import async_sessionmaker

    monkeypatch.setenv("REPORT_LOCAL_PATH", str(tmp_path))

    body = (await client.post("/quick-scan", json={"url": "https://hasreport.test"})).json()

    store = LocalTranscriptStore(tmp_path)
    payload = {"scan_id": body["scan_id"], "summary": {"assets_found": 1}}
    storage_pointer = await store.put(json.dumps(payload).encode())

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(
            Report(
                scan_id=body["scan_id"],
                format=ReportFormat.DASHBOARD,
                storage_pointer=storage_pointer,
            )
        )
        await session.commit()

    headers = {"X-Org-Id": body["org_id"]}
    resp = await client.get(f"/scans/{body['scan_id']}/report", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == payload


async def test_report_not_reachable_from_another_org(
    client, no_quick_scan_dispatch, quick_scan_enabled
):
    body = (await client.post("/quick-scan", json={"url": "https://private.test"})).json()

    other_org = (
        await client.post("/organizations", json={"name": "Other", "slug": "other-org"})
    ).json()
    resp = await client.get(
        f"/scans/{body['scan_id']}/report", headers={"X-Org-Id": other_org["id"]}
    )
    assert resp.status_code == 404
