from __future__ import annotations

from unittest.mock import AsyncMock, patch

from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState
from sentinel_db.models import Asset, Organization, Scan, ScanPhase, Target
from sentinel_recon import DiscoveredAsset, HttpProbeResult, ReconResult
from sentinel_worker_app.scan_runner import run_scan
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _make_recon_result(root_domain: str, *, degraded: bool = True) -> ReconResult:
    return ReconResult(
        root_domain=root_domain,
        assets=[
            DiscoveredAsset(
                host=root_domain,
                source="root_domain",
                ips=["1.2.3.4"],
                http_probes=[
                    HttpProbeResult(
                        url=f"https://{root_domain}/", status_code=200, title="Acme", server="nginx"
                    )
                ],
            )
        ],
        tool_availability={"subfinder": not degraded, "httpx": not degraded, "tlsx": not degraded},
        wildcard_dns_suspected=False,
        notes=["a note"] if degraded else [],
    )


async def _make_scannable_target(session: AsyncSession, *, domain="acme.test") -> Target:
    org = Organization(name="Acme", slug=f"acme-{domain}", wrapped_data_key=b"key")
    session.add(org)
    await session.flush()
    target = Target(
        organization_id=org.id,
        root_domain=domain,
        display_name="Acme",
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()
    return target


async def _make_scan(session: AsyncSession, target: Target) -> Scan:
    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.flush()
    await session.commit()
    return scan


async def test_run_scan_pauses_after_surface_mapping_with_degraded_notes(db_engine):
    """No personas are configured on this target, so AUTH_ESTABLISHING and
    CRAWLING both run in their honest degraded-anonymous-only mode (real
    browser, real network — `acme.test` doesn't resolve, so the crawl finds
    nothing, which the crawler treats as a normal empty result, not a
    failure) and the scan still progresses all the way to SURFACE_MAPPING
    before pausing, since the check engines past that are the only thing
    still unimplemented."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        target = await _make_scannable_target(session)
        scan = await _make_scan(session, target)
        scan_id = str(scan.id)

    with patch(
        "sentinel_worker_app.scan_runner.run_recon",
        new=AsyncMock(return_value=_make_recon_result(target.root_domain, degraded=True)),
    ):
        await run_scan(scan_id)

    async with factory() as session:
        refreshed = await session.get(Scan, scan.id)
        assert refreshed.state == ScanState.PAUSED
        assert refreshed.paused_from == ScanState.SURFACE_MAPPING
        assert refreshed.is_degraded is True
        assert any("a note" in r for r in refreshed.degraded_reasons)
        assert any("No personas" in r for r in refreshed.degraded_reasons)
        assert any("not implemented" in r for r in refreshed.degraded_reasons)

        phases = (
            (await session.execute(select(ScanPhase).where(ScanPhase.scan_id == scan.id)))
            .scalars()
            .all()
        )
        phase_by_name = {p.name: p for p in phases}
        assert phase_by_name[ScanPhaseName.SCOPE_VERIFYING].status == PhaseStatus.COMPLETED
        assert phase_by_name[ScanPhaseName.RECON].status == PhaseStatus.COMPLETED
        assert phase_by_name[ScanPhaseName.RECON].stats_json["assets_found"] == 1
        assert phase_by_name[ScanPhaseName.AUTH_ESTABLISHING].status == PhaseStatus.COMPLETED
        assert phase_by_name[ScanPhaseName.AUTH_ESTABLISHING].stats_json["personas_configured"] == 0
        assert phase_by_name[ScanPhaseName.CRAWLING].status == PhaseStatus.COMPLETED
        assert phase_by_name[ScanPhaseName.CRAWLING].stats_json["personas_crawled"] == ["anonymous"]
        assert phase_by_name[ScanPhaseName.SURFACE_MAPPING].status == PhaseStatus.COMPLETED

        assets = (
            (await session.execute(select(Asset).where(Asset.scan_id == scan.id))).scalars().all()
        )
        assert len(assets) == 1
        assert assets[0].host == target.root_domain
        assert assets[0].ip_addresses == ["1.2.3.4"]
        assert assets[0].http_probes[0]["status_code"] == 200


async def test_run_scan_blocks_when_target_not_scannable(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        org = Organization(name="Acme2", slug="acme2", wrapped_data_key=b"key")
        session.add(org)
        await session.flush()
        target = Target(
            organization_id=org.id,
            root_domain="notverified.test",
            display_name="Not Verified",
            ownership_verified=False,
            authorization_accepted=False,
        )
        session.add(target)
        await session.flush()
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.flush()
        await session.commit()
        scan_id = str(scan.id)

    with patch("sentinel_worker_app.scan_runner.run_recon", new=AsyncMock()) as mock_recon:
        await run_scan(scan_id)
        mock_recon.assert_not_called()

    async with factory() as session:
        refreshed = await session.get(Scan, scan.id)
        assert refreshed.state == ScanState.BLOCKED_UNVERIFIED
        assert refreshed.finished_at is not None

        phases = (
            (await session.execute(select(ScanPhase).where(ScanPhase.scan_id == scan.id)))
            .scalars()
            .all()
        )
        assert len(phases) == 1
        assert phases[0].name == ScanPhaseName.SCOPE_VERIFYING
        assert phases[0].status == PhaseStatus.FAILED


async def test_run_scan_is_a_noop_for_missing_scan(db_engine):
    # Should log and return cleanly, not raise.
    await run_scan("00000000-0000-0000-0000-000000000000")
