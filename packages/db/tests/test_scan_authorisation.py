"""ScanAuthorisation against a real Postgres: the unique scan, the cascade,
and what happens to a carried-over reference when the earlier scan goes."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sentinel_db.models import Organization, Scan, ScanAuthorisation, Target
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.integration


async def _target(session) -> Target:
    org = Organization(name="Acme", slug="acme-auth", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(organization_id=org.id, root_domain="acme.test", display_name="Acme")
    session.add(target)
    await session.flush()
    return target


def _row(scan: Scan, target: Target, **kwargs) -> ScanAuthorisation:
    values = {
        "scan_id": scan.id,
        "target_id": target.id,
        "username": "alice",
        "accepted_at": datetime.now(UTC),
        "statement_version": "1",
        "statement_text": "I confirm ...",
        "client_name": "Acme Ltd",
        "target_name": "acme.test",
        "tools": ["dir_bruteforce"],
        "all_ports_confirmed": False,
        "target_environment": "production",
        "options_snapshot": {"speed": "gentle"},
    }
    values.update(kwargs)
    return ScanAuthorisation(**values)


async def test_a_scan_carries_who_requested_it_and_one_authorisation(session_factory):
    async with session_factory() as session:
        target = await _target(session)
        scan = Scan(target_id=target.id, requested_by="alice")
        session.add(scan)
        await session.flush()
        session.add(_row(scan, target, client_ip="203.0.113.7", user_agent="curl/8"))
        await session.commit()

    async with session_factory() as session:
        got = (await session.execute(select(Scan))).scalar_one()
        assert got.requested_by == "alice"
        row = (await session.execute(select(ScanAuthorisation))).scalar_one()
        assert row.tools == ["dir_bruteforce"]
        assert row.options_snapshot == {"speed": "gentle"}
        assert row.client_ip == "203.0.113.7"
        assert row.carried_over_from_scan_id is None


async def test_requested_by_is_optional(session_factory):
    async with session_factory() as session:
        target = await _target(session)
        session.add(Scan(target_id=target.id))
        await session.commit()
        assert (await session.execute(select(Scan))).scalar_one().requested_by is None


async def test_a_scan_has_at_most_one_authorisation(session_factory):
    async with session_factory() as session:
        target = await _target(session)
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.flush()
        session.add(_row(scan, target))
        await session.commit()
        session.add(_row(scan, target, username="bob"))
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_deleting_the_scan_deletes_its_authorisation(session_factory):
    async with session_factory() as session:
        target = await _target(session)
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.flush()
        session.add(_row(scan, target))
        await session.commit()
        await session.delete(scan)
        await session.commit()
        assert (await session.execute(select(ScanAuthorisation))).first() is None


async def test_deleting_the_earlier_scan_keeps_the_record_but_clears_the_link(session_factory):
    async with session_factory() as session:
        target = await _target(session)
        old = Scan(target_id=target.id)
        new = Scan(target_id=target.id)
        session.add_all([old, new])
        await session.flush()
        session.add(_row(new, target, carried_over_from_scan_id=old.id))
        await session.commit()
        old_id = old.id
        await session.delete(old)
        await session.commit()
        session.expire_all()
        row = (await session.execute(select(ScanAuthorisation))).scalar_one()
        assert row.carried_over_from_scan_id is None
        assert row.scan_id != old_id
