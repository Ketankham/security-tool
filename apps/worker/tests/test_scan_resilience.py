"""v1 #2: scans keep going after a failed login, and never stay stuck.

- every login failing → the scan still completes, anonymously, degraded;
- an unexpected exception → FAILED with a readable reason (no auto-retry);
- a worker restart mid-scan → the cut-off scan is closed as FAILED.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState
from sentinel_db.enums import CredentialKind
from sentinel_db.models import Credential, Organization, Persona, Scan, ScanPhase, Target
from sentinel_recon import ReconResult
from sentinel_worker_app.scan_runner import fail_interrupted_scans, mark_scan_failed, run_scan
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

MASTER_KEY = "pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="


def _empty_recon(root_domain: str) -> ReconResult:
    return ReconResult(
        root_domain=root_domain,
        assets=[],
        tool_availability={},
        wildcard_dns_suspected=False,
        notes=[],
    )


async def _target_with_broken_login(session) -> Target:
    crypto = EnvelopeCrypto(LocalMasterKeyProvider([MASTER_KEY.encode()]))
    data_key = crypto.generate_data_key()
    org = Organization(
        name="R", slug=f"r-{uuid.uuid4().hex[:8]}", wrapped_data_key=crypto.wrap_data_key(data_key)
    )
    session.add(org)
    await session.flush()
    target = Target(
        organization_id=org.id,
        root_domain="acme.test",
        display_name="Acme",
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()
    cred = Credential(kind=CredentialKind.PASSWORD, ciphertext=crypto.encrypt(data_key, b"pw"))
    session.add(cred)
    await session.flush()
    # Saved before login URLs were validated: the worker refuses it, so this
    # login fails without needing a network.
    session.add(
        Persona(
            target_id=target.id,
            label="Admin",
            role_name="admin",
            credential_id=cred.id,
            login_recipe={
                "start_url": "https://evil.example.org/login",
                "steps": [{"action": "fill_secret", "selector": "#p", "credential_ref": "pw"}],
                "success_assertion": {"kind": "url_contains", "value": "/home"},
            },
        )
    )
    await session.flush()
    return target


async def test_scan_continues_anonymously_when_every_login_fails(db_engine, monkeypatch):
    monkeypatch.setenv("KMS_MASTER_KEY", MASTER_KEY)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        target = await _target_with_broken_login(session)
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.commit()

    with patch(
        "sentinel_worker_app.scan_runner.run_recon",
        new=AsyncMock(return_value=_empty_recon(target.root_domain)),
    ):
        await run_scan(str(scan.id))

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.COMPLETE
        assert row.started_at is not None
        assert row.is_degraded is True
        reasons = " | ".join(row.degraded_reasons)
        assert "Login for 'Admin' failed" in reasons
        assert "continued as an anonymous visitor" in reasons
        phases = {p.name: p for p in row.phases}
        assert phases[ScanPhaseName.AUTH_ESTABLISHING].status == PhaseStatus.FAILED
        assert phases[ScanPhaseName.CRAWLING].stats_json["personas_crawled"] == ["anonymous"]
        persona = (
            await session.execute(select(Persona).where(Persona.target_id == target.id))
        ).scalar_one()
        assert persona.is_available is False


async def _scan_in(session, state: ScanState, *, running_phase: ScanPhaseName | None = None):
    org = Organization(name="F", slug=f"f-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(organization_id=org.id, root_domain="f.test", display_name="F")
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id, state=state)
    session.add(scan)
    await session.flush()
    if running_phase is not None:
        session.add(ScanPhase(scan_id=scan.id, name=running_phase, status=PhaseStatus.RUNNING))
    await session.commit()
    return scan


async def test_mark_scan_failed_records_reason_and_closes_the_running_phase(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, ScanState.CRAWLING, running_phase=ScanPhaseName.CRAWLING)

    assert await mark_scan_failed(str(scan.id), "unexpected error (RuntimeError: boom).")

    async with factory() as session:
        row = await session.get(Scan, scan.id, options=[selectinload(Scan.phases)])
        assert row.state == ScanState.FAILED
        assert row.fail_reason == (
            "The scan stopped during crawling: unexpected error (RuntimeError: boom)."
        )
        assert row.finished_at is not None
        assert row.phases[0].status == PhaseStatus.FAILED

    # Already terminal: left alone.
    assert not await mark_scan_failed(str(scan.id), "again")


@pytest.mark.parametrize("state", [ScanState.QUEUED, ScanState.COMPLETE])
async def test_restart_sweep_leaves_queued_and_finished_scans_alone(db_engine, state):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(session, state)
    await fail_interrupted_scans()
    async with factory() as session:
        assert (await session.get(Scan, scan.id)).state == state


async def test_restart_sweep_fails_scans_cut_off_mid_run(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = await _scan_in(
            session, ScanState.TESTING, running_phase=ScanPhaseName.ACCESS_CONTROL
        )
    assert await fail_interrupted_scans() >= 1
    async with factory() as session:
        row = await session.get(Scan, scan.id)
        assert row.state == ScanState.FAILED
        assert "worker restarted" in row.fail_reason
