"""The passive-checks phase end to end: crawl a real local site, run the
checks through the real HttpEngine, store the findings, read them back."""

from __future__ import annotations

import uuid

from sentinel_db.enums import FindingConfidence
from sentinel_db.models import Evidence, Finding, Organization, Scan, Target, TranscriptRecord
from sentinel_worker_app.config import Settings
from sentinel_worker_app.scan_runner import _run_crawling, _run_passive
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

MASTER_KEY = "pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="


async def test_passive_phase_finds_confirms_and_stores_findings(
    db_engine, redis_client, browser, persona_app_server, tmp_path
):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    root_domain = persona_app_server.split("://", 1)[1].split(":")[0]
    async with factory() as session:
        org = Organization(name="P", slug=f"p-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
        session.add(org)
        await session.flush()
        target = Target(
            organization_id=org.id,
            root_domain=root_domain,
            display_name="Local site",
            ownership_verified=True,
            authorization_accepted=True,
        )
        session.add(target)
        await session.flush()
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.commit()

        surfaces = await _run_crawling(
            target=target,
            scope_rules=[],
            configured_personas=[],
            in_memory_sessions={},
            redis_client=redis_client,
            browser=browser,
            root_url=f"{persona_app_server}/",
        )
        settings = Settings(
            kms_master_key=MASTER_KEY, storage_local_path=str(tmp_path / "transcripts")
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
        assert not stats.failed
        assert stats.requests > 15
        assert stats.origins == [persona_app_server]

        session.add_all(records)
        session.add_all(findings)
        await session.commit()

    async with factory() as session:
        rows = (
            (
                await session.execute(
                    select(Finding)
                    .where(Finding.scan_id == scan.id)
                    .options(selectinload(Finding.evidence), selectinload(Finding.verification))
                )
            )
            .scalars()
            .all()
        )
        by_rule = {f.rule_id: f for f in rows}

        # The test site sends none of the security headers.
        for rule in ("headers.csp_missing", "headers.clickjacking", "headers.nosniff_missing"):
            finding = by_rule[rule]
            assert finding.confidence is FindingConfidence.CONFIRMED
            assert finding.verification.passed and finding.verification.reproduced_count >= 2
            assert finding.remediation["steps"] and finding.remediation["summary"]
            assert finding.reproduction["curl"].startswith("curl ")
            assert finding.evidence and finding.evidence[0].role == "response-headers"
        # It is plain HTTP with no HTTPS: reported, and re-checked.
        assert by_rule["tls.http_only"].confidence is FindingConfidence.CONFIRMED
        assert by_rule["tls.http_only"].evidence == []
        # It is not a site with exposed files: no false alarms from a 404-ing app.
        assert not [r for r in by_rule if r.startswith("exposed.")]

        # Every evidence row points at a stored transcript of this scan.
        transcripts = {
            t.transcript_id
            for t in (
                await session.execute(
                    select(TranscriptRecord).where(TranscriptRecord.scan_id == scan.id)
                )
            ).scalars()
        }
        evidence = (await session.execute(select(Evidence))).scalars().all()
        assert evidence and all(e.transcript_id in transcripts for e in evidence)

    assert stats.confirmed == len([f for f in rows if f.confidence is FindingConfidence.CONFIRMED])
