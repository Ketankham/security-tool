"""PortService against a real Postgres: the defaults, the one row per (scan,
address, port, protocol), the cascade from the scan and the link to a tool run;
and the tool-run columns this change added."""

from __future__ import annotations

import pytest
from sentinel_db.models import Organization, PortService, Scan, Target, ToolRunRecord
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.integration


async def _scan(session) -> Scan:
    org = Organization(name="Acme", slug="acme-ports", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(organization_id=org.id, root_domain="acme.test", display_name="Acme")
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.flush()
    return scan


def _port(scan: Scan, **kwargs) -> PortService:
    values = {
        "scan_id": scan.id,
        "ip": "203.0.113.7",
        "hosts": ["acme.test"],
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "confidence": "port_guess",
        "found_by": "naabu",
    }
    values.update(kwargs)
    return PortService(**values)


async def test_a_port_keeps_what_was_found_and_defaults_the_rest(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add(_port(scan, service="https"))
        await session.commit()
    async with session_factory() as session:
        row = (await session.execute(select(PortService))).scalar_one()
        assert (row.ip, row.port, row.protocol, row.state) == ("203.0.113.7", 443, "tcp", "open")
        assert row.hosts == ["acme.test"] and row.scripts == {}  # empty, never null
        assert (row.service, row.confidence, row.found_by) == ("https", "port_guess", "naabu")
        assert row.product is None and row.version is None and row.extra_info is None
        assert row.cdn is None and row.tool_run_id is None
        assert row.created_at is not None and row.updated_at is not None


async def test_json_columns_round_trip(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add(
            _port(
                scan,
                hosts=["a.acme.test", "b.acme.test"],
                scripts={"ssh-hostkey": "256 3b:a1 (ECDSA)", "banner": "SSH-2.0"},
                confidence="detected",
                found_by="nmap",
            )
        )
        await session.commit()
    async with session_factory() as session:
        row = (await session.execute(select(PortService))).scalar_one()
        assert row.hosts == ["a.acme.test", "b.acme.test"]
        assert row.scripts["ssh-hostkey"] == "256 3b:a1 (ECDSA)"


async def test_one_row_per_scan_address_port_and_protocol(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add(_port(scan))
        await session.commit()
        scan_id = scan.id
        session.add(_port(scan))  # the same (scan, ip, port, protocol)
        with pytest.raises(IntegrityError) as excinfo:
            await session.commit()
        assert "uq_port_services_scan_ip_port" in str(excinfo.value)
        await session.rollback()
        # another port, another address, another protocol are all fine
        session.add_all(
            [
                PortService(
                    scan_id=scan_id,
                    ip="203.0.113.7",
                    port=80,
                    protocol="tcp",
                    state="open",
                    confidence="port_guess",
                    found_by="naabu",
                    hosts=[],
                ),
                PortService(
                    scan_id=scan_id,
                    ip="203.0.113.8",
                    port=443,
                    protocol="tcp",
                    state="open",
                    confidence="port_guess",
                    found_by="naabu",
                    hosts=[],
                ),
                PortService(
                    scan_id=scan_id,
                    ip="203.0.113.7",
                    port=443,
                    protocol="udp",
                    state="open",
                    confidence="port_guess",
                    found_by="naabu",
                    hosts=[],
                ),
            ]
        )
        await session.commit()
        assert len((await session.execute(select(PortService))).scalars().all()) == 4


async def test_the_same_address_and_port_may_appear_in_another_scan(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        other = Scan(target_id=scan.target_id)
        session.add(other)
        await session.flush()
        session.add_all([_port(scan), _port(other)])
        await session.commit()


async def test_deleting_the_scan_deletes_its_ports(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add(_port(scan))
        await session.commit()
        await session.execute(delete(Scan).where(Scan.id == scan.id))
        await session.commit()
        assert (await session.execute(select(PortService))).first() is None


async def test_deleting_the_tool_run_keeps_the_port_and_clears_the_link(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        run = ToolRunRecord(scan_id=scan.id, seq=1, phase="recon", tool="naabu", status="ok")
        session.add(run)
        await session.flush()
        session.add(_port(scan, tool_run_id=run.id))
        await session.commit()
        await session.execute(delete(ToolRunRecord).where(ToolRunRecord.id == run.id))
        await session.commit()
    async with session_factory() as session:
        row = (await session.execute(select(PortService))).scalar_one()
        assert row.tool_run_id is None


async def test_a_tool_run_has_an_empty_second_output_unless_one_is_given(session_factory):
    async with session_factory() as session:
        scan = await _scan(session)
        session.add_all(
            [
                ToolRunRecord(scan_id=scan.id, seq=1, phase="recon", tool="naabu", status="ok"),
                ToolRunRecord(
                    scan_id=scan.id,
                    seq=2,
                    phase="recon",
                    tool="nmap",
                    status="ok",
                    extra_output="Nmap scan report\n",
                    extra_output_label="nmap normal output (-oN)",
                ),
            ]
        )
        await session.commit()
    async with session_factory() as session:
        naabu, nmap = (
            (await session.execute(select(ToolRunRecord).order_by(ToolRunRecord.seq)))
            .scalars()
            .all()
        )
        assert naabu.extra_output == "" and naabu.extra_output_label is None
        assert nmap.extra_output == "Nmap scan report\n"
        assert nmap.extra_output_label == "nmap normal output (-oN)"


async def test_a_raw_insert_without_the_new_columns_gets_the_server_default(session_factory):
    """Rows written by code that predates the column (and the migration's backfill)."""
    async with session_factory() as session:
        scan = await _scan(session)
        await session.execute(
            text(
                "insert into tool_runs (id, scan_id, seq, phase, tool, status, command, "
                "timed_out, results_count, stdout, stderr, stdout_truncated, stderr_truncated, "
                "created_at, updated_at) values (gen_random_uuid(), :scan, 1, 'recon', 'x', 'ok', "
                "'', false, 0, '', '', false, false, now(), now())"
            ),
            {"scan": scan.id},
        )
        await session.commit()
        run = (await session.execute(select(ToolRunRecord))).scalar_one()
        assert run.extra_output == "" and run.extra_output_label is None
