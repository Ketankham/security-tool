"""DiscoveredPath against a real Postgres: the defaults, the cascade from the
scan and what happens to the links to a tool run and a finding."""

from __future__ import annotations

import pytest
from sentinel_db.enums import FindingSeverity
from sentinel_db.models import (
    DiscoveredPath,
    Finding,
    Organization,
    Scan,
    Target,
    ToolRunRecord,
)
from sqlalchemy import delete, select, text

pytestmark = pytest.mark.integration


async def _scan(session) -> Scan:
    org = Organization(name="Acme", slug="acme-paths", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(organization_id=org.id, root_domain="acme.test", display_name="Acme")
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.flush()
    return scan


def _path(scan: Scan, **kwargs) -> DiscoveredPath:
    values = {
        "scan_id": scan.id,
        "origin": "https://acme.test",
        "path": "/.env",
        "url": "https://acme.test/.env",
        "method": "GET",
        "status_code": 200,
        "category": "config",
        "wordlist": "sentinel-core",
        "verdict": "found",
    }
    values.update(kwargs)
    return DiscoveredPath(**values)


async def test_a_path_keeps_what_was_found_and_defaults_the_rest(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add(_path(scan, content_length=120, words=8, lines=4, content_type="text/plain"))
        await session.commit()
    async with session_factory() as session:
        row = (await session.execute(select(DiscoveredPath))).scalar_one()
        assert (row.status_code, row.content_length, row.words, row.lines) == (200, 120, 8, 4)
        assert row.crawl_seed is False  # off unless the step turns it on
        assert row.tool_run_id is None and row.finding_id is None
        assert row.rule_id is None and row.note is None and row.redirect_location is None
        assert row.created_at is not None


async def test_the_database_default_for_crawl_seed_is_false(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        await session.commit()
        await session.execute(
            text(
                "insert into discovered_paths (id, scan_id, origin, path, url, method, "
                "status_code, category, wordlist, verdict, created_at, updated_at) values "
                "(gen_random_uuid(), :scan, 'o', '/p', 'u', 'GET', 200, 'common', 'w', 'found', "
                "now(), now())"
            ),
            {"scan": scan.id},
        )
        await session.commit()
        row = (await session.execute(select(DiscoveredPath))).scalar_one()
        assert row.crawl_seed is False


async def test_deleting_the_scan_deletes_its_paths(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add_all([_path(scan), _path(scan, path="/admin/", url="https://acme.test/admin/")])
        await session.commit()
        await session.delete(scan)
        await session.commit()
        assert (await session.execute(select(DiscoveredPath))).first() is None


async def test_deleting_the_tool_run_or_the_finding_only_clears_the_link(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        run = ToolRunRecord(scan_id=scan.id, seq=1, phase="recon", tool="ffuf", status="ok")
        finding = Finding(
            scan_id=scan.id,
            fingerprint="a" * 64,
            rule_id="exposed.env_file",
            title="Environment file (.env) is publicly downloadable",
            severity=FindingSeverity.CRITICAL,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
        )
        session.add_all([run, finding])
        await session.flush()
        session.add(
            _path(
                scan,
                tool_run_id=run.id,
                finding_id=finding.id,
                verdict="confirmed",
                rule_id="exposed.env_file",
            )
        )
        await session.commit()
        await session.execute(delete(ToolRunRecord).where(ToolRunRecord.id == run.id))
        await session.execute(delete(Finding).where(Finding.id == finding.id))
        await session.commit()
        session.expire_all()
        row = (await session.execute(select(DiscoveredPath))).scalar_one()
        assert row.tool_run_id is None and row.finding_id is None
        assert row.verdict == "confirmed" and row.rule_id == "exposed.env_file"
