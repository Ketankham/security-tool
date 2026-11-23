"""With the address guard on, a scan of a site on a non-public address sends
nothing to it: the crawl visits no page and the passive checks make no
request, and the activity log says why."""

from __future__ import annotations

import uuid

from sentinel_db.models import Organization, Scan, Target
from sentinel_worker_app.config import Settings
from sentinel_worker_app.scan_log import ScanLog
from sentinel_worker_app.scan_runner import _run_crawling, _run_passive
from sqlalchemy.ext.asyncio import async_sessionmaker

MASTER_KEY = "pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="


async def test_crawl_and_passive_checks_refuse_a_site_on_a_private_address(
    db_engine, redis_client, browser, persona_app_server, tmp_path, monkeypatch
):
    monkeypatch.setenv("ALLOW_PRIVATE_ADDRESSES", "false")  # the worker reads it per call
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    root_domain = persona_app_server.split("://", 1)[1].split(":")[0]  # 127.0.0.1
    async with factory() as session:
        org = Organization(name="G", slug=f"g-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
        session.add(org)
        await session.flush()
        target = Target(
            organization_id=org.id,
            root_domain=root_domain,
            display_name="Loopback site",
            ownership_verified=True,
            authorization_accepted=True,
        )
        session.add(target)
        await session.flush()
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.commit()

        log = ScanLog(scan.id)
        surfaces = await _run_crawling(
            target=target,
            scope_rules=[],
            configured_personas=[],
            in_memory_sessions={},
            redis_client=redis_client,
            browser=browser,
            root_url=f"{persona_app_server}/",
            scan_log=log,
        )
        assert surfaces[0].pages_visited == 0
        assert surfaces[0].endpoints == []
        skipped = [e for e in log._buffer if "non-public address" in e.message]
        assert skipped and skipped[0].level == "warn"

        settings = Settings(
            kms_master_key=MASTER_KEY,
            storage_local_path=str(tmp_path / "transcripts"),
            allow_private_addresses=False,
        )
        stats, findings, records = await _run_passive(
            scan=scan,
            target=target,
            scope_rules=[],
            surfaces=surfaces,
            personas=[],
            in_memory_sessions={},
            settings=settings,
            redis_client=redis_client,
        )
        assert findings == []
        assert records == []  # no request was made, so nothing was recorded
