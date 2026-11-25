"""GET /scans/{id}/ports (what port scanning found, in address order, scoped to
the caller's org) and the tool-run additions that go with it: the second output
(nmap's normal report) and ``?stream=extra``."""

from __future__ import annotations

import uuid

import pytest
from sentinel_core.state_machine import ScanState
from sentinel_db.models import PortService, Scan, ToolRunRecord
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration

FIELDS = {
    "id",
    "scan_id",
    "tool_run_id",
    "ip",
    "hosts",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
    "extra_info",
    "confidence",
    "scripts",
    "cdn",
    "found_by",
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


def _row(scan_id, ip, port, **extra) -> PortService:
    values = {
        "scan_id": scan_id,
        "ip": ip,
        "hosts": ["shop.test"],
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "confidence": "port_guess",
        "found_by": "naabu",
        "scripts": {},
    }
    values.update(extra)
    return PortService(**values)


async def _scan(db_engine, target_id) -> Scan:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        scan = Scan(target_id=uuid.UUID(target_id), state=ScanState.COMPLETE)
        session.add(scan)
        await session.commit()
        return scan


async def test_a_scan_without_port_scanning_lists_nothing(client, db_engine):
    headers, target = await _org_target(client, "ports-empty")
    scan = await _scan(db_engine, target["id"])
    resp = await client.get(f"/scans/{scan.id}/ports", headers=headers)
    assert resp.status_code == 200 and resp.json() == []


async def test_ports_come_back_in_numeric_address_order_then_port(client, db_engine):
    headers, target = await _org_target(client, "ports-order")
    scan = await _scan(db_engine, target["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add_all(
            [
                _row(scan.id, "10.0.0.10", 443),
                _row(scan.id, "10.0.0.9", 8080),
                _row(scan.id, "10.0.0.9", 22),
                _row(scan.id, "2001:db8::1", 80),
                _row(scan.id, "9.9.9.9", 25),
            ]
        )
        await session.commit()
    rows = (await client.get(f"/scans/{scan.id}/ports", headers=headers)).json()
    assert [(r["ip"], r["port"]) for r in rows] == [
        ("9.9.9.9", 25),  # numeric, not string, order: 9.9.9.9 before 10.0.0.9
        ("10.0.0.9", 22),
        ("10.0.0.9", 8080),
        ("10.0.0.10", 443),
        ("2001:db8::1", 80),
    ]
    assert all(set(r) == FIELDS for r in rows)


async def test_every_stored_field_is_returned(client, db_engine):
    headers, target = await _org_target(client, "ports-fields")
    scan = await _scan(db_engine, target["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        run = ToolRunRecord(scan_id=scan.id, seq=1, phase="recon", tool="nmap", status="ok")
        session.add(run)
        await session.flush()
        session.add(
            _row(
                scan.id,
                "198.51.100.4",
                22,
                hosts=["a.shop.test", "b.shop.test"],
                service="ssh",
                product="OpenSSH",
                version="8.9p1",
                extra_info="protocol 2.0",
                confidence="detected",
                scripts={"ssh-hostkey": "256 3b:a1 (ECDSA)"},
                cdn="cloudflare",
                found_by="nmap",
                tool_run_id=run.id,
            )
        )
        await session.commit()
        run_id = str(run.id)
    (row,) = (await client.get(f"/scans/{scan.id}/ports", headers=headers)).json()
    assert row["hosts"] == ["a.shop.test", "b.shop.test"]
    assert (row["service"], row["product"], row["version"]) == ("ssh", "OpenSSH", "8.9p1")
    assert row["extra_info"] == "protocol 2.0" and row["confidence"] == "detected"
    assert row["scripts"] == {"ssh-hostkey": "256 3b:a1 (ECDSA)"}
    assert row["cdn"] == "cloudflare" and row["found_by"] == "nmap"
    assert row["tool_run_id"] == run_id and row["scan_id"] == str(scan.id)
    assert row["protocol"] == "tcp" and row["state"] == "open"


async def test_ports_are_scoped_to_the_callers_org(client, db_engine):
    headers_a, target_a = await _org_target(client, "ports-a")
    headers_b, _ = await _org_target(client, "ports-b")
    scan = await _scan(db_engine, target_a["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(_row(scan.id, "9.9.9.9", 443))
        await session.commit()
    assert (await client.get(f"/scans/{scan.id}/ports", headers=headers_a)).status_code == 200
    assert (await client.get(f"/scans/{scan.id}/ports", headers=headers_b)).status_code == 404
    assert (await client.get(f"/scans/{scan.id}/ports")).status_code == 401
    assert (await client.get(f"/scans/{uuid.uuid4()}/ports", headers=headers_a)).status_code == 404


async def test_ports_only_list_this_scans_rows(client, db_engine):
    headers, target = await _org_target(client, "ports-own")
    first = await _scan(db_engine, target["id"])
    second = await _scan(db_engine, target["id"])
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add(_row(first.id, "9.9.9.9", 22))
        session.add(_row(second.id, "9.9.9.9", 25))
        await session.commit()
    rows = (await client.get(f"/scans/{first.id}/ports", headers=headers)).json()
    assert [r["port"] for r in rows] == [22]


# --- Tool runs: the second output --------------------------------------------------------------


async def _runs(db_engine, target_id):
    scan = await _scan(db_engine, target_id)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        session.add_all(
            [
                ToolRunRecord(
                    scan_id=scan.id,
                    seq=1,
                    phase="recon",
                    tool="naabu",
                    version="v2.7.0",
                    command="naabu -host 9.9.9.9",
                    status="ok",
                    stdout="line\n",
                ),
                ToolRunRecord(
                    scan_id=scan.id,
                    seq=2,
                    phase="recon",
                    tool="nmap",
                    version="7.93",
                    command="nmap -sT 9.9.9.9",
                    status="ok",
                    stdout="<nmaprun/>",
                    extra_output="Nmap scan report for 9.9.9.9\n22/tcp open ssh\n",
                    extra_output_label="nmap normal output (-oN)",
                ),
            ]
        )
        await session.commit()
    return scan


async def test_tool_runs_say_how_much_extra_output_they_hold(client, db_engine):
    headers, target = await _org_target(client, "extra-list")
    scan = await _runs(db_engine, target["id"])
    runs = (await client.get(f"/scans/{scan.id}/tool-runs", headers=headers)).json()
    assert [(r["tool"], r["extra_output_chars"], r["extra_output_label"]) for r in runs] == [
        ("naabu", 0, None),
        (
            "nmap",
            len("Nmap scan report for 9.9.9.9\n22/tcp open ssh\n"),
            "nmap normal output (-oN)",
        ),
    ]


async def test_stream_extra_downloads_the_second_output_with_its_label(client, db_engine):
    headers, target = await _org_target(client, "extra-get")
    scan = await _runs(db_engine, target["id"])
    runs = (await client.get(f"/scans/{scan.id}/tool-runs", headers=headers)).json()
    out = await client.get(
        f"/scans/{scan.id}/tool-runs/{runs[1]['id']}/output?stream=extra", headers=headers
    )
    assert out.status_code == 200
    assert out.text.startswith(
        "# nmap 7.93 (ok) — extra (nmap normal output (-oN))\n# $ nmap -sT 9.9.9.9\n"
    )
    assert "22/tcp open ssh" in out.text
    assert "attachment" in out.headers["content-disposition"]
    assert out.headers["content-disposition"].endswith('-2-nmap-extra.txt"')


async def test_stream_extra_of_a_run_without_one_is_a_404_and_the_old_streams_still_work(
    client, db_engine
):
    headers, target = await _org_target(client, "extra-none")
    scan = await _runs(db_engine, target["id"])
    runs = (await client.get(f"/scans/{scan.id}/tool-runs", headers=headers)).json()
    none = await client.get(
        f"/scans/{scan.id}/tool-runs/{runs[0]['id']}/output?stream=extra", headers=headers
    )
    assert none.status_code == 404
    assert none.json()["detail"] == "This tool run has no additional output."
    stdout = await client.get(
        f"/scans/{scan.id}/tool-runs/{runs[0]['id']}/output?stream=stdout", headers=headers
    )
    assert stdout.status_code == 200 and "— stdout" in stdout.text
    bad = await client.get(
        f"/scans/{scan.id}/tool-runs/{runs[0]['id']}/output?stream=other", headers=headers
    )
    assert bad.status_code == 422


async def test_stream_extra_is_scoped_to_the_callers_org(client, db_engine):
    headers_a, target_a = await _org_target(client, "extra-a")
    headers_b, _ = await _org_target(client, "extra-b")
    scan = await _runs(db_engine, target_a["id"])
    runs = (await client.get(f"/scans/{scan.id}/tool-runs", headers=headers_a)).json()
    resp = await client.get(
        f"/scans/{scan.id}/tool-runs/{runs[1]['id']}/output?stream=extra", headers=headers_b
    )
    assert resp.status_code == 404
