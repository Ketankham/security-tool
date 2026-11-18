"""The activity log writer: buffered, redacted, capped, resumable, and a real
scan leaves a readable trail in it."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_db.enums import CredentialKind
from sentinel_db.models import Credential, Organization, Persona, Scan, ScanEvent, Target
from sentinel_recon import ReconResult
from sentinel_worker_app import scan_log as scan_log_module
from sentinel_worker_app.scan_log import ScanLog
from sentinel_worker_app.scan_runner import run_scan
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

MASTER_KEY = "pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="


async def _scan(db_engine) -> uuid.UUID:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        org = Organization(name="L", slug=f"l-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
        session.add(org)
        await session.flush()
        target = Target(organization_id=org.id, root_domain="l.test", display_name="L")
        session.add(target)
        await session.flush()
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.commit()
        return scan.id


async def _events(db_engine, scan_id) -> list[ScanEvent]:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        return list(
            (
                await session.execute(
                    select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.seq)
                )
            )
            .scalars()
            .all()
        )


async def test_events_are_numbered_redacted_and_flushed(db_engine):
    scan_id = await _scan(db_engine)
    log = ScanLog(scan_id)
    log.add_secrets(["SESSIONVALUE123"])
    log.add("auth", "cookie SESSIONVALUE123 loaded", persona="Teacher", note="SESSIONVALUE123 x")
    log.add("crawl", "Visited https://l.test/cb?code=abc123&page=2", count=3)
    await log.flush()
    await log.flush()  # a second flush with nothing buffered is harmless

    rows = await _events(db_engine, scan_id)
    assert [r.seq for r in rows] == [1, 2]
    assert "SESSIONVALUE123" not in rows[0].message + str(rows[0].data)
    assert rows[0].persona == "Teacher"
    assert "abc123" not in rows[1].message and "page=2" in rows[1].message
    assert rows[1].data == {"count": 3}


async def test_log_is_capped_and_errors_still_get_through(db_engine, monkeypatch):
    monkeypatch.setattr(scan_log_module, "MAX_EVENTS", 5)
    scan_id = await _scan(db_engine)
    log = ScanLog(scan_id)
    for i in range(20):
        log.add("crawl", f"line {i}")
    log.add("scan", "the scan crashed", level="error")
    await log.flush()
    rows = await _events(db_engine, scan_id)
    messages = [r.message for r in rows]
    assert messages[:5] == [f"line {i}" for i in range(5)]
    assert "log is full" in messages[5]
    assert messages[-1] == "the scan crashed"
    assert len(rows) == 7  # 5 lines, the "log is full" notice, and the error


async def test_resume_continues_the_sequence(db_engine):
    scan_id = await _scan(db_engine)
    first = ScanLog(scan_id)
    first.add("scan", "one")
    first.add("scan", "two")
    await first.flush()
    second = await ScanLog.resume(scan_id)
    second.add("scan", "three", level="error")
    await second.flush()
    assert [(r.seq, r.message) for r in await _events(db_engine, scan_id)] == [
        (1, "one"),
        (2, "two"),
        (3, "three"),
    ]


async def test_a_failing_database_never_breaks_the_caller(db_engine):
    scan_id = uuid.uuid4()  # no such scan: the insert violates the foreign key
    log = ScanLog(scan_id)
    log.add("scan", "orphan line")
    await log.flush()  # must not raise


async def test_a_scan_leaves_a_readable_secret_free_trail(db_engine, monkeypatch):
    monkeypatch.setenv("KMS_MASTER_KEY", MASTER_KEY)
    crypto = EnvelopeCrypto(LocalMasterKeyProvider([MASTER_KEY.encode()]))
    data_key = crypto.generate_data_key()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        org = Organization(
            name="T",
            slug=f"t-{uuid.uuid4().hex[:8]}",
            wrapped_data_key=crypto.wrap_data_key(data_key),
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
        cred = Credential(
            kind=CredentialKind.PASSWORD, ciphertext=crypto.encrypt(data_key, b"TopSecretPW99")
        )
        session.add(cred)
        await session.flush()
        session.add(
            Persona(
                target_id=target.id,
                label="Admin",
                role_name="admin",
                credential_id=cred.id,
                login_recipe={
                    "start_url": "https://evil.example.org/login",  # refused by the worker
                    "steps": [{"action": "fill_secret", "selector": "#p", "credential_ref": "pw"}],
                    "success_assertion": {"kind": "url_contains", "value": "/home"},
                },
            )
        )
        scan = Scan(target_id=target.id, options={"speed": "gentle", "depth": "quick"})
        session.add(scan)
        await session.commit()

    recon = ReconResult(
        root_domain="acme.test",
        assets=[],
        tool_availability={},
        wildcard_dns_suspected=False,
        notes=["subfinder is not installed"],
    )
    with patch("sentinel_worker_app.scan_runner.run_recon", new=AsyncMock(return_value=recon)):
        await run_scan(str(scan.id))

    rows = await _events(db_engine, scan.id)
    text = "\n".join(f"[{r.stage}] {r.message}" for r in rows)
    assert "Scan started for acme.test (speed 2 requests/second, up to 30 pages" in text
    assert "[recon] subfinder is not installed" in text
    assert "Logging in as 'Admin'" in text
    assert "Login failed: Login blocked" in text
    assert "No login worked" in text
    assert "Crawling" in text and "Logged-out crawl done" in text
    assert "Scan complete" in text
    assert "TopSecretPW99" not in text
    assert [r.seq for r in rows] == list(range(1, len(rows) + 1))
