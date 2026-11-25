"""The real naabu binary (skipped when it is not on PATH) against plain TCP
listeners on 127.0.0.1 that these tests start, driven through build_args /
run_naabu exactly as the worker will. Nothing here scans any other address.

Note the ``pps`` values: the worker uses 50/100/200 (all ports never above
100); the tests that must finish quickly use a higher rate against loopback
only, and the rate test measures the real thing at 200."""

import asyncio
import random
import re
import shutil
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sentinel_recon import naabu_wrapper
from sentinel_recon.naabu_wrapper import OpenPort, run_naabu

pytestmark = pytest.mark.skipif(shutil.which("naabu") is None, reason="naabu is not installed")

LOOPBACK = "127.0.0.1"

# Ports in naabu's top-1000 list (checked against the real v2.7.0 binary).
# The first one that is free on the machine is used.
TOP_1000_CANDIDATES = [8080, 8000, 8888, 8081, 8008, 8443, 9090, 9000, 3000, 5000, 4000, 7000]


class Listener:
    """A plain TCP listener that accepts and immediately closes connections."""

    def __init__(self, port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((LOOPBACK, port))
        self.sock.listen(128)
        self.port = port
        self.connections = 0
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self._stop = True
        self.sock.close()
        self._thread.join(timeout=2)


@contextmanager
def listening(candidates: list[int]) -> Iterator[Listener]:
    for port in candidates:
        try:
            listener = Listener(port)
        except OSError:
            continue
        try:
            yield listener
        finally:
            listener.close()
        return
    pytest.skip(f"none of the candidate ports {candidates} is free on this machine")


def high_port_candidates() -> list[int]:
    """Ports well outside naabu's top-1000 (which has a few in the 32768 and
    49152 ranges): 47123 first, then random picks between 41000 and 48000."""
    return [47123, *random.sample(range(41000, 48000), 20)]


def naabu_pids() -> set[int]:
    pids = set()
    for comm in Path("/proc").glob("[0-9]*/comm"):
        try:
            if comm.read_text().strip() == "naabu":
                pids.add(int(comm.parent.name))
        except (OSError, ValueError):
            continue
    return pids


def tcp_active_opens() -> int | None:
    """The kernel's count of outgoing TCP connection attempts (system wide)."""
    try:
        lines = Path("/proc/net/snmp").read_text().splitlines()
        header = next(line for line in lines if line.startswith("Tcp:") and "ActiveOpens" in line)
        values = lines[lines.index(header) + 1].split()
        return int(values[header.split().index("ActiveOpens")])
    except (OSError, StopIteration, ValueError, IndexError):
        return None


async def no_naabu_left(before: set[int], within: float = 3.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if not (naabu_pids() - before):
            return True
        await asyncio.sleep(0.1)
    return False


# --- finding ports -----------------------------------------------------------------------


async def test_a_listener_on_a_high_port_is_found_only_with_all_ports():
    before = naabu_pids()
    with listening(high_port_candidates()) as listener:
        top = await run_naabu(LOOPBACK, all_ports=False, pps=1000, timeout_s=120)
        assert top.result.ran and top.result.returncode == 0 and top.error is None
        assert listener.port not in {p.port for p in top.ports}

        everything = await run_naabu(LOOPBACK, all_ports=True, pps=5000, timeout_s=180)
        assert everything.result.ran and everything.result.returncode == 0
        assert everything.error is None and everything.stop_reason is None
        found = {p.port: p for p in everything.ports}
        assert listener.port in found
        assert found[listener.port].ip == LOOPBACK
        assert found[listener.port].protocol == "tcp"
        assert everything.suspicious is False
        # `-verify` made a second connection to the open port
        assert listener.connections >= 2
    assert await no_naabu_left(before)


async def test_a_listener_inside_the_top_1000_is_found_by_the_default_scan():
    before = naabu_pids()
    seen: list[OpenPort] = []
    with listening(TOP_1000_CANDIDATES) as listener:
        run = await run_naabu(
            LOOPBACK, all_ports=False, pps=1000, timeout_s=120, on_port=seen.append
        )
        assert run.error is None and run.stop_reason is None
        assert listener.port in {p.port for p in run.ports}
        assert listener.port in {p.port for p in seen}  # streamed to the callback too
        assert all(p.ip == LOOPBACK for p in run.ports)
        # the rest of the output is banner/log noise, which parse_line ignores
        assert "Running CONNECT scan with non root privileges" in (
            run.result.stdout + run.result.stderr
        )
    assert await no_naabu_left(before)


async def test_several_listeners_are_all_found_and_none_twice():
    listeners: list[Listener] = []
    try:
        for port in TOP_1000_CANDIDATES:
            try:
                listeners.append(Listener(port))
            except OSError:
                continue
            if len(listeners) == 3:
                break
        if len(listeners) < 2:
            pytest.skip("fewer than two candidate ports are free")
        run = await run_naabu(LOOPBACK, all_ports=False, pps=1000, timeout_s=120)
    finally:
        for listener in listeners:
            listener.close()
    ports = [p.port for p in run.ports]
    assert {listener.port for listener in listeners} <= set(ports)
    assert len(ports) == len(set(ports))


async def test_nothing_listening_gives_no_ports_and_a_clean_exit():
    # no listeners are started here; unrelated services on this machine may
    # still be listening, so only the shape of the result is asserted
    run = await run_naabu(LOOPBACK, all_ports=False, pps=1000, timeout_s=120)
    assert run.result.ran and run.result.returncode == 0 and run.error is None
    assert run.suspicious is False


# --- how fast it goes ---------------------------------------------------------------------


async def test_the_connection_rate_stays_near_the_requested_rate():
    """Top-1000 with 2 passes is about 2000 connection attempts. At 200 per
    second that takes about 10 s; unthrottled it takes about 1 s. The kernel's
    own count of outgoing connections, over the run, is the measured rate."""
    pps = 200
    before_pids = naabu_pids()
    opens_before = tcp_active_opens()
    started = time.monotonic()
    run = await run_naabu(LOOPBACK, all_ports=False, pps=pps, timeout_s=120)
    elapsed = time.monotonic() - started
    opens_after = tcp_active_opens()
    assert run.error is None and run.stop_reason is None

    expected_s = naabu_wrapper.TOP_PORTS_COUNT * 2 / pps  # 10 s
    assert elapsed >= 0.6 * expected_s, f"finished in {elapsed:.1f}s: the rate limit is not applied"
    assert elapsed <= naabu_wrapper.default_timeout_s(all_ports=False, pps=pps)

    if opens_before is not None and opens_after is not None:
        measured = (opens_after - opens_before) / elapsed
        # other processes on the machine can only add connections, so this
        # is an upper bound on what naabu itself did
        assert measured <= 1.5 * pps, f"{measured:.0f} connections/s measured, asked for {pps}"
    assert await no_naabu_left(before_pids)


# --- stopping it --------------------------------------------------------------------------


async def test_cancel_stops_a_real_scan_and_leaves_no_process():
    before = naabu_pids()

    async def cancel_after_a_moment():
        await asyncio.sleep(0)
        return "tester" if time.monotonic() - started > 2.5 else None

    started = time.monotonic()
    # 25 pps: this would take about 80 s if it were not cancelled
    run = await run_naabu(
        LOOPBACK, all_ports=False, pps=25, timeout_s=120, cancel_check=cancel_after_a_moment
    )
    elapsed = time.monotonic() - started
    assert run.result.cancelled is True and run.result.cancelled_by == "tester"
    assert run.stop_reason == "cancelled" and run.error is None
    assert elapsed < 20
    assert await no_naabu_left(before)


async def test_timeout_stops_a_real_scan_and_leaves_no_process():
    before = naabu_pids()
    started = time.monotonic()
    run = await run_naabu(LOOPBACK, all_ports=True, pps=20, timeout_s=3)
    assert run.result.timed_out is True and run.stop_reason == "timed out"
    assert time.monotonic() - started < 15
    assert await no_naabu_left(before)


async def test_cancelling_the_awaiting_task_leaves_no_process():
    before = naabu_pids()
    task = asyncio.create_task(run_naabu(LOOPBACK, all_ports=True, pps=20, timeout_s=300))
    await asyncio.sleep(2.0)
    assert naabu_pids() - before  # it is running
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await no_naabu_left(before)


# --- housekeeping -------------------------------------------------------------------------


async def test_naabu_writes_its_config_to_a_private_home_not_the_real_one(tmp_path, monkeypatch):
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    monkeypatch.setenv("HOME", str(real_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(real_home / "xdg"))
    run = await run_naabu(LOOPBACK, all_ports=False, pps=2000, timeout_s=60)
    assert run.result.returncode == 0
    assert list(real_home.iterdir()) == []


async def test_version_is_read_from_the_real_binary():
    version = await naabu_wrapper.version()
    assert version is not None and re.fullmatch(r"v\d+\.\d+\.\d+", version)
    assert await naabu_wrapper.is_available() is True
