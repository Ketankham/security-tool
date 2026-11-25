"""GET /scans/{id}/paths: what directory brute force found, in the order the
dashboard shows it, scoped to the caller's org."""

from __future__ import annotations

import uuid

import pytest
from sentinel_core.state_machine import ScanState
from sentinel_db.enums import FindingConfidence, FindingSeverity
from sentinel_db.models import DiscoveredPath, Finding, Scan
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration

FIELDS = {
    "id",
    "scan_id",
    "tool_run_id",
    "origin",
    "path",
    "url",
    "method",
    "status_code",
    "content_length",
    "words",
    "lines",
    "content_type",
    "redirect_location",
    "category",
    "wordlist",
    "verdict",
    "rule_id",
    "finding_id",
    "note",
    "crawl_seed",
}


async def _org_target(client, slug):
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets", json={"root_domain": f"{slug}.test", "display_name": "x"}, headers=headers
        )
    ).json()
    return headers, target


def _row(scan_id, path, *, category="config", verdict="found", status=200, **extra):
    values = {
        "scan_id": scan_id,
        "origin": "https://shop.test",
        "path": path,
        "url": f"https://shop.test{path}",
        "method": "GET",
        "status_code": status,
        "category": category,
        "wordlist": "sentinel-core",
        "verdict": verdict,
    }
    values.update(extra)
    return DiscoveredPath(**values)


async def _scan(db_engine, target_id) -> Scan:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = Scan(target_id=uuid.UUID(target_id), state=ScanState.COMPLETE)
        session.add(scan)
        await session.commit()
        return scan


async def test_a_scan_without_paths_lists_nothing(client, db_engine):
    headers, target = await _org_target(client, "paths-empty")
    scan = await _scan(db_engine, target["id"])
    resp = await client.get(f"/scans/{scan.id}/paths", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_paths_come_back_confirmed_first_then_category_then_path(client, db_engine):
    headers, target = await _org_target(client, "paths-order")
    scan = await _scan(db_engine, target["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        finding = Finding(
            scan_id=scan.id,
            fingerprint="f" * 64,
            rule_id="exposed.git_repository",
            title="Git repository is publicly downloadable",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.PROBABLE,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
        )
        session.add(finding)
        await session.flush()
        session.add_all(
            [
                _row(scan.id, "/zeta", category="admin"),
                _row(scan.id, "/api/v1", category="api"),
                _row(scan.id, "/admin/", category="admin"),
                _row(scan.id, "/old.zip", category="backup", method="HEAD"),
                _row(
                    scan.id,
                    "/.git/HEAD",
                    category="vcs",
                    verdict="confirmed",
                    rule_id="exposed.git_repository",
                    finding_id=finding.id,
                ),
                _row(
                    scan.id,
                    "/.env",
                    category="config",
                    verdict="confirmed",
                    rule_id="exposed.env_file",
                ),
                _row(
                    scan.id,
                    "/maybe",
                    category="config",
                    verdict="not_confirmed",
                    note="did not hold up",
                ),
            ]
        )
        await session.commit()
        finding_id = str(finding.id)

    rows = (await client.get(f"/scans/{scan.id}/paths", headers=headers)).json()
    assert [(r["verdict"], r["category"], r["path"]) for r in rows] == [
        ("confirmed", "config", "/.env"),
        ("confirmed", "vcs", "/.git/HEAD"),
        ("found", "admin", "/admin/"),
        ("found", "admin", "/zeta"),
        ("found", "api", "/api/v1"),
        ("found", "backup", "/old.zip"),
        ("not_confirmed", "config", "/maybe"),
    ]
    assert all(set(r) == FIELDS for r in rows)
    git = rows[1]
    assert git["finding_id"] == finding_id
    assert git["rule_id"] == "exposed.git_repository"
    assert git["scan_id"] == str(scan.id)
    assert rows[5]["method"] == "HEAD"
    assert rows[6]["note"] == "did not hold up"
    assert rows[0]["crawl_seed"] is False


async def test_every_stored_field_is_returned(client, db_engine):
    headers, target = await _org_target(client, "paths-fields")
    scan = await _scan(db_engine, target["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(
            _row(
                scan.id,
                "/portal",
                category="admin",
                status=302,
                content_length=0,
                words=1,
                lines=1,
                content_type="text/html",
                redirect_location="/portal/",
                crawl_seed=True,
            )
        )
        await session.commit()
    (row,) = (await client.get(f"/scans/{scan.id}/paths", headers=headers)).json()
    assert row["status_code"] == 302
    assert row["content_length"] == 0 and row["words"] == 1 and row["lines"] == 1
    assert row["content_type"] == "text/html"
    assert row["redirect_location"] == "/portal/"
    assert row["crawl_seed"] is True
    assert row["origin"] == "https://shop.test" and row["url"] == "https://shop.test/portal"
    assert row["wordlist"] == "sentinel-core" and row["tool_run_id"] is None


async def test_paths_are_scoped_to_the_callers_org(client, db_engine):
    headers_a, target_a = await _org_target(client, "paths-a")
    headers_b, _ = await _org_target(client, "paths-b")
    scan = await _scan(db_engine, target_a["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(_row(scan.id, "/.env", verdict="confirmed"))
        await session.commit()
    assert (await client.get(f"/scans/{scan.id}/paths", headers=headers_a)).status_code == 200
    assert (await client.get(f"/scans/{scan.id}/paths", headers=headers_b)).status_code == 404
    assert (await client.get(f"/scans/{scan.id}/paths")).status_code == 401  # no X-Org-Id
    unknown = await client.get(f"/scans/{uuid.uuid4()}/paths", headers=headers_a)
    assert unknown.status_code == 404


async def test_paths_only_list_this_scans_rows(client, db_engine):
    headers, target = await _org_target(client, "paths-own")
    first = await _scan(db_engine, target["id"])
    second = await _scan(db_engine, target["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(_row(first.id, "/a"))
        session.add(_row(second.id, "/b"))
        await session.commit()
    rows = (await client.get(f"/scans/{first.id}/paths", headers=headers)).json()
    assert [r["path"] for r in rows] == ["/a"]
