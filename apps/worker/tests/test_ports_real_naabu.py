"""The port scanning step with the REAL naabu (skipped when it is not on PATH),
through the real adapter, against TCP listeners on 127.0.0.1 that these tests
start. ALLOW_PRIVATE_ADDRESSES is on for worker tests (conftest), so the
loopback address passes the public-address check. Nothing here scans any other
address."""

from __future__ import annotations

import shutil
import time

import pytest
import sentinel_worker_test_fixture_port_support as ps
from sentinel_core import scan_options
from sentinel_worker_app.ports_adapter import PortTools

pytestmark = pytest.mark.skipif(shutil.which("naabu") is None, reason="naabu is not installed")


def recon():
    return ps.recon_ips(("127.0.0.1", ["127.0.0.1"]))


async def test_the_default_scan_finds_a_top_1000_listener_not_a_high_port_one_and_stays_at_its_rate(
    db_engine,
):
    before = ps.naabu_pids()
    with (
        ps.listening(ps.TOP_1000_CANDIDATES) as common,
        ps.listening(ps.high_port_candidates()) as high,
    ):
        opens_before = ps.tcp_active_opens()
        started = time.monotonic()
        result = await ps.run_ports_step(
            db_engine,
            recon(),
            tools=PortTools(),  # real naabu; nmap is irrelevant on Light
            profile="light",
            speed_pps=200,
        )
        elapsed = time.monotonic() - started
        opens_after = ps.tcp_active_opens()

        assert result.error is None
        rows = await result.by_port()
        assert ("127.0.0.1", common.port) in rows
        assert ("127.0.0.1", high.port) not in rows  # outside the top 1,000
        row = rows[("127.0.0.1", common.port)]
        assert row.state == "open" and row.found_by == "naabu"
        assert row.confidence == "port_guess" and row.hosts == ["127.0.0.1"]
        (run,) = await result.tool_runs()
        assert (run.tool, run.status, run.exit_code) == ("naabu", "ok", 0)
        assert "-scan-type c" in run.command and "-rate 200" in run.command
        assert "-top-ports 1000" in run.command

    expected_s = 1000 * 2 / 200  # two passes of 1,000 ports at 200 per second
    assert elapsed >= 0.6 * expected_s, f"{elapsed:.1f}s: the rate limit is not applied"
    if opens_before is not None and opens_after is not None:
        measured = (opens_after - opens_before) / elapsed
        assert measured <= 1.5 * 200, f"{measured:.0f} connections/s measured, asked for 200"
    assert await ps.no_naabu_left(before)
    assert result.log.has("Port scan of 1 IP(s): top 1,000 TCP ports, connect scan, 200 packets/s")
    assert any("(127.0.0.1): " in m and "open:" in m for m in result.log.messages)


async def test_all_ports_with_both_opt_ins_finds_the_high_port_listener(db_engine, monkeypatch):
    # The honest ceiling is 100 packets/s (11 minutes for 65,535 ports); loopback
    # tests raise both constants so the run takes seconds. The golden rate tests
    # (test_ports_adapter) pin the real values.
    monkeypatch.setattr(
        scan_options, "PORT_PACKETS_PER_SECOND", {"gentle": 50, "normal": 100, "fast": 5000}
    )
    monkeypatch.setattr(scan_options, "ALL_PORTS_MAX_PPS", 5000)
    before = ps.naabu_pids()
    with ps.listening(ps.high_port_candidates()) as high:
        result = await ps.run_ports_step(
            db_engine,
            recon(),
            tools=PortTools(),
            profile="full",
            options={"port_scan": True, "all_ports": True},
            all_ports_confirmed=True,
            speed_pps=5000,
            allow_private=True,
        )
        assert result.error is None
        rows = await result.by_port()
        assert ("127.0.0.1", high.port) in rows
        assert result.stats.all_ports_ips == 1
        runs = await result.tool_runs()
        naabu_run = next(r for r in runs if r.tool == "naabu")
        assert "-p 1-65535" in naabu_run.command and "-rate 5000" in naabu_run.command
        assert naabu_run.status == "ok"
        assert rows[("127.0.0.1", high.port)].service is None  # no guess for an unknown port
    assert await ps.no_naabu_left(before)


async def test_without_all_ports_the_same_high_port_listener_is_missed_on_the_full_profile(
    db_engine, monkeypatch
):
    monkeypatch.setattr(
        scan_options, "PORT_PACKETS_PER_SECOND", {"gentle": 50, "normal": 100, "fast": 1000}
    )
    with ps.listening(ps.high_port_candidates()) as high:
        result = await ps.run_ports_step(
            db_engine,
            recon(),
            tools=PortTools(),
            profile="full",
            options={"port_scan": True, "all_ports": True},  # the option alone is not enough
            all_ports_confirmed=False,
            speed_pps=1000,
        )
        assert ("127.0.0.1", high.port) not in await result.by_port()
        assert result.stats.all_ports_ips == 0


async def test_the_address_guard_keeps_the_real_naabu_off_loopback_when_private_is_not_allowed(
    db_engine,
):
    before = ps.naabu_pids()
    with ps.listening(ps.TOP_1000_CANDIDATES) as listener:
        result = await ps.run_ports_step(
            db_engine, recon(), tools=PortTools(), allow_private=False, speed_pps=200
        )
        assert listener.connections == 0  # not one connection, not even a probe
    assert await result.rows() == [] and await result.tool_runs() == []
    assert result.stats.refused_ips == 1
    assert ps.naabu_pids() == before
