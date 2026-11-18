"""The activity log, found endpoints and evidence viewer: what a reviewer
uses to check what a scan actually did."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sentinel_core.state_machine import ScanState
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.models import Asset, Endpoint, Scan, ScanEvent, TranscriptRecord
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration


async def _org_target(client, slug):
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets", json={"root_domain": f"{slug}.test", "display_name": "x"}, headers=headers
        )
    ).json()
    return headers, target


async def _scan_with_events(db_engine, target_id, n=6):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = Scan(target_id=uuid.UUID(target_id), state=ScanState.COMPLETE)
        session.add(scan)
        await session.flush()
        now = datetime.now(UTC)
        stages = ["scope", "recon", "auth", "crawl", "crawl", "access_control"]
        for i in range(n):
            session.add(
                ScanEvent(
                    scan_id=scan.id,
                    seq=i + 1,
                    at=now + timedelta(seconds=i),
                    stage=stages[i % len(stages)],
                    level="warn" if i == 2 else "info",
                    persona="Teacher" if stages[i % len(stages)] == "crawl" else None,
                    message=f"event {i + 1}",
                    data={},
                )
            )
        await session.commit()
        return scan.id


async def test_events_are_listed_filtered_and_paged(client, db_engine):
    headers, target = await _org_target(client, "ev-list")
    scan_id = await _scan_with_events(db_engine, target["id"])
    base = f"/scans/{scan_id}/events"

    body = (await client.get(base, headers=headers)).json()
    assert [e["seq"] for e in body["events"]] == [1, 2, 3, 4, 5, 6]
    assert body["total"] == 6 and body["last_seq"] == 6

    newer = (await client.get(base, params={"after_seq": 4}, headers=headers)).json()
    assert [e["seq"] for e in newer["events"]] == [5, 6]

    nothing = (await client.get(base, params={"after_seq": 6}, headers=headers)).json()
    assert nothing["events"] == [] and nothing["last_seq"] == 6 and nothing["total"] == 6

    crawl = (await client.get(base, params={"stage": "crawl"}, headers=headers)).json()
    assert [e["seq"] for e in crawl["events"]] == [4, 5] and crawl["total"] == 6
    assert (await client.get(base, params={"level": "warn"}, headers=headers)).json()["events"][0][
        "seq"
    ] == 3
    by_persona = (await client.get(base, params={"persona": "Teacher"}, headers=headers)).json()
    assert len(by_persona["events"]) == 2

    page = (await client.get(base, params={"limit": 2}, headers=headers)).json()
    assert [e["seq"] for e in page["events"]] == [1, 2] and page["last_seq"] == 2


async def test_log_download_is_plain_text(client, db_engine):
    headers, target = await _org_target(client, "ev-dl")
    scan_id = await _scan_with_events(db_engine, target["id"], n=3)
    resp = await client.get(f"/scans/{scan_id}/events/download", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "attachment" in resp.headers["content-disposition"]
    assert "[INFO ] [scope] event 1" in resp.text
    assert "[WARN ] [auth] event 3" in resp.text
    assert "redacted" in resp.text.splitlines()[2]


async def test_insight_is_scoped_to_the_callers_org(client, db_engine):
    headers_a, target_a = await _org_target(client, "ev-a")
    headers_b, _ = await _org_target(client, "ev-b")
    scan_id = await _scan_with_events(db_engine, target_a["id"])
    for path in ("events", "events/download", "endpoints", f"transcripts/{'a' * 64}"):
        resp = await client.get(f"/scans/{scan_id}/{path}", headers=headers_b)
        assert resp.status_code == 404, path
    assert (await client.get(f"/scans/{scan_id}/events", headers=headers_a)).status_code == 200


async def test_endpoints_list_who_reached_what(client, db_engine):
    headers, target = await _org_target(client, "ev-ep")
    scan_id = await _scan_with_events(db_engine, target["id"], n=1)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        asset = Asset(scan_id=scan_id, host="www.ev-ep.test", discovery_source="crawl")
        session.add(asset)
        await session.flush()
        for method, path, source, who in (
            ("GET", "/dashboard", "rendered_crawl", ["anonymous", "p1"]),
            ("POST", "/api/save", "js_extraction", ["p1"]),
        ):
            session.add(
                Endpoint(
                    asset_id=asset.id,
                    method=method,
                    path_template=path,
                    discovery_source=source,
                    discovered_by_persona_ids=who,
                )
            )
        await session.commit()
    rows = (await client.get(f"/scans/{scan_id}/endpoints", headers=headers)).json()
    assert [(r["method"], r["path_template"], r["persona_ids"]) for r in rows] == [
        ("POST", "/api/save", ["p1"]),
        ("GET", "/dashboard", ["anonymous", "p1"]),
    ]
    assert rows[0]["host"] == "www.ev-ep.test"


async def test_transcript_viewer_only_serves_this_scans_records(
    client, db_engine, tmp_path, monkeypatch
):
    monkeypatch.setenv("STORAGE_LOCAL_PATH", str(tmp_path))
    headers, target = await _org_target(client, "ev-tr")
    scan_id = await _scan_with_events(db_engine, target["id"], n=1)
    store = LocalTranscriptStore(tmp_path)
    doc = {
        "request": {"method": "GET", "url": "https://x.test/", "headers": {}},
        "response": {"status_code": 200, "headers": {}, "body": "A" * 25_000},
    }
    transcript_id = await store.put(json.dumps(doc).encode())
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(
            TranscriptRecord(
                transcript_id=transcript_id,
                scan_id=scan_id,
                persona_id=None,
                method="GET",
                url="https://x.test/",
                status_code=200,
            )
        )
        await session.commit()

    got = await client.get(f"/scans/{scan_id}/transcripts/{transcript_id}", headers=headers)
    assert got.status_code == 200
    assert got.json()["response"]["body"].endswith("(truncated)")

    # A transcript that exists in storage but isn't indexed for this scan: 404.
    other_id = await store.put(b'{"request": {}, "response": null}')
    missing = await client.get(f"/scans/{scan_id}/transcripts/{other_id}", headers=headers)
    assert missing.status_code == 404
