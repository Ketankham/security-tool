"""Helpers shared by the port scanning tests: TCP listeners on 127.0.0.1,
recon results that carry addresses, fake naabu/nmap runners (for the adapter's
own logic) and fake naabu/nmap scripts on PATH (for the real wrappers), and a
runner that executes the step against a database."""

from __future__ import annotations

import asyncio
import os
import random
import shlex
import socket
import stat
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sentinel_db.models import PortService, Scan, ToolRunRecord
from sentinel_recon import (
    DiscoveredAsset,
    HttpProbeResult,
    ReconResult,
    naabu_wrapper,
    nmap_wrapper,
)
from sentinel_recon.naabu_wrapper import NaabuRun, OpenPort
from sentinel_recon.nmap_wrapper import NmapRun, ServiceInfo
from sentinel_recon.tooling import ToolRunResult
from sentinel_worker_app.ports_adapter import PortTools
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

LOOPBACK = "127.0.0.1"

# Ports inside naabu's top-1000 list (checked against naabu v2.7.0). The first
# one that is free on the machine is used.
TOP_1000_CANDIDATES = [8080, 8000, 8888, 8081, 8008, 8443, 9090, 9000, 3000, 5000, 4000, 7000]


# --- Real listeners on 127.0.0.1 --------------------------------------------------------


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
    """Ports well outside naabu's top-1000: 47123 first, then random picks."""
    return [47123, *random.sample(range(41000, 48000), 20)]


def naabu_pids() -> set[int]:
    return _pids_named("naabu")


def _pids_named(name: str) -> set[int]:
    pids = set()
    for comm in Path("/proc").glob("[0-9]*/comm"):
        try:
            if comm.read_text().strip() == name:
                pids.add(int(comm.parent.name))
        except (OSError, ValueError):
            continue
    return pids


async def no_naabu_left(before: set[int], within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if not (naabu_pids() - before):
            return True
        await asyncio.sleep(0.1)
    return False


def tcp_active_opens() -> int | None:
    """The kernel's count of outgoing TCP connection attempts (system wide)."""
    try:
        lines = Path("/proc/net/snmp").read_text().splitlines()
        header = next(line for line in lines if line.startswith("Tcp:") and "ActiveOpens" in line)
        values = lines[lines.index(header) + 1].split()
        return int(values[header.split().index("ActiveOpens")])
    except (OSError, StopIteration, ValueError, IndexError):
        return None


# --- Recon results with addresses ---------------------------------------------------------


def recon_ips(
    *assets: tuple,
    root: str | None = None,
    notes: list[str] | None = None,
) -> ReconResult:
    """A recon result from ``(host, [ips])`` or ``(host, [ips], scope_status)``
    tuples. The first host is the root domain unless ``root`` says otherwise.
    Hosts that are in scope answer HTTP on port 80 (``live``)."""
    built = []
    for entry in assets:
        host, ips = entry[0], list(entry[1])
        status = entry[2] if len(entry) > 2 else "in_scope"
        probes = (
            [HttpProbeResult(url=f"http://{host}", status_code=200, title=None, server=None)]
            if status == "in_scope"
            else []
        )
        built.append(
            DiscoveredAsset(
                host=host,
                source="root_domain" if host == (root or assets[0][0]) else "subfinder",
                ips=ips,
                http_probes=probes,
                scope_status=status,
            )
        )
    return ReconResult(
        root_domain=root or assets[0][0],
        assets=built,
        tool_availability={},
        wildcard_dns_suspected=False,
        notes=notes or [],
    )


# --- Fake runners (the adapter's own logic) ------------------------------------------------


def naabu_result(ip: str, *, all_ports: bool, pps: float, **kwargs) -> ToolRunResult:
    command = shlex.join(
        [naabu_wrapper.BINARY, *naabu_wrapper.build_args(ip, all_ports=all_ports, pps=pps)]
    )
    now = datetime.now(UTC)
    values = {
        "ran": True,
        "command": command,
        "returncode": 0,
        "started_at": now,
        "finished_at": now,
        "stdout": "",
    }
    values.update(kwargs)
    return ToolRunResult(**values)


class FakeNaabu:
    """Stands in for naabu_wrapper.run_naabu. ``ports`` maps an IP to the open
    ports it reports (an int, or an OpenPort for more detail). ``behaviour``
    maps an IP to "fail" (non-zero exit), "timeout", "cancel" or "suspicious"
    (150 open ports). ``on_call(ip)`` runs at the start of each call (advance a
    fake clock, press cancel, ...)."""

    def __init__(
        self,
        ports: dict[str, list] | None = None,
        *,
        behaviour: dict[str, str] | None = None,
        on_call: Callable[[str], None] | None = None,
    ) -> None:
        self.ports = ports or {}
        self.behaviour = behaviour or {}
        self.on_call = on_call
        self.calls: list[dict] = []

    async def __call__(
        self, ip, *, all_ports, pps, timeout_s=None, cancel_check=None, on_port=None
    ) -> NaabuRun:
        self.calls.append({"ip": ip, "all_ports": all_ports, "pps": pps, "timeout_s": timeout_s})
        if self.on_call is not None:
            self.on_call(ip)
        mode = self.behaviour.get(ip)
        found = [
            p if isinstance(p, OpenPort) else OpenPort(ip=ip, port=p)
            for p in self.ports.get(ip, [])
        ]
        if mode == "suspicious":
            found = [OpenPort(ip=ip, port=p) for p in range(1000, 1150)]
        if mode == "cancel":
            return NaabuRun(
                result=naabu_result(
                    ip,
                    all_ports=all_ports,
                    pps=pps,
                    cancelled=True,
                    cancelled_by="dana",
                    returncode=None,
                ),
                ports=found,
                stop_reason="cancelled",
            )
        if mode == "timeout":
            return NaabuRun(
                result=naabu_result(
                    ip, all_ports=all_ports, pps=pps, timed_out=True, returncode=None
                ),
                ports=found,
                stop_reason="timed out",
            )
        if mode == "fail":
            return NaabuRun(
                result=naabu_result(ip, all_ports=all_ports, pps=pps, returncode=2),
                ports=[],
                error="naabu exited with code 2: boom",
            )
        return NaabuRun(
            result=naabu_result(ip, all_ports=all_ports, pps=pps),
            ports=found,
            suspicious=len(found) > naabu_wrapper.SUSPICIOUS_OPEN_PORTS,
        )

    @property
    def ips(self) -> list[str]:
        return [c["ip"] for c in self.calls]


def service(port: int, name: str | None = "http", **kwargs) -> ServiceInfo:
    values = {"state": "open", "method": "probed", "confidence": 10, "protocol": "tcp"}
    values.update(kwargs)
    return ServiceInfo(port=port, service=name, **values)


class FakeNmap:
    """Stands in for nmap_wrapper.run_nmap. ``services`` maps an IP to the
    ServiceInfo list it reports. ``behaviour`` maps an IP to "skip", "fail"
    (unparseable output) or "cancel"."""

    def __init__(
        self,
        services: dict[str, list[ServiceInfo]] | None = None,
        *,
        behaviour: dict[str, str] | None = None,
        normal_output: str = "Nmap scan report\n",
    ) -> None:
        self.services = services or {}
        self.behaviour = behaviour or {}
        self.normal_output = normal_output
        self.calls: list[dict] = []

    async def __call__(
        self, ip, ports, *, environment, pps, timeout_s=1000.0, cancel_check=None
    ) -> NmapRun:
        self.calls.append(
            {
                "ip": ip,
                "ports": list(ports),
                "environment": environment,
                "pps": pps,
                "timeout_s": timeout_s,
            }
        )
        mode = self.behaviour.get(ip)
        now = datetime.now(UTC)
        result = ToolRunResult(
            ran=True,
            command=f"nmap -sT -sV -p {','.join(map(str, ports))} {ip}",
            returncode=0,
            started_at=now,
            finished_at=now,
            stdout="<nmaprun/>",
        )
        if mode == "skip":
            return NmapRun(
                result=ToolRunResult(ran=False), skipped_reason=nmap_wrapper.SKIPPED_TOO_MANY_PORTS
            )
        if mode == "cancel":
            return NmapRun(
                result=ToolRunResult(
                    ran=True,
                    command=result.command,
                    cancelled=True,
                    cancelled_by="dana",
                    started_at=now,
                    finished_at=now,
                ),
                services=list(self.services.get(ip, [])),
                stop_reason="cancelled",
            )
        if mode == "fail":
            return NmapRun(result=result, parse_error="nmap output was not nmap XML")
        return NmapRun(
            result=result,
            services=list(self.services.get(ip, [])),
            normal_output=self.normal_output,
        )


def fake_tools(
    naabu: FakeNaabu | None = None,
    nmap: FakeNmap | None = None,
    *,
    nmap_installed: bool = True,
    naabu_installed: bool = True,
) -> PortTools:
    async def naabu_available() -> bool:
        return naabu_installed

    async def nmap_available() -> bool:
        return nmap_installed

    async def naabu_version() -> str | None:
        return "v2.7.0"

    async def nmap_version() -> str | None:
        return "7.93"

    return PortTools(
        naabu=naabu or FakeNaabu(),
        nmap=nmap or FakeNmap(),
        naabu_available=naabu_available,
        nmap_available=nmap_available,
        naabu_version=naabu_version,
        nmap_version=nmap_version,
    )


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- Fake binaries on PATH (the real wrappers run them) --------------------------------------


def install_fake_binary(tmp_path: Path, monkeypatch, name: str, body: str) -> Path:
    """A python script called ``name`` first on PATH."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / name
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return script


def no_binaries_on_path(tmp_path: Path, monkeypatch) -> None:
    """PATH with nothing on it but python's own directory (no naabu, no nmap)."""
    empty = tmp_path / "empty-bin"
    empty.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(empty))


# --- Running the step against a database -------------------------------------------------------


class PortsResult:
    def __init__(self, stats, log, scan_id, target_id, factory, error=None) -> None:
        self.stats = stats
        self.log = log
        self.scan_id = scan_id
        self.target_id = target_id
        self.factory = factory
        self.error = error

    async def rows(self) -> list[PortService]:
        async with self.factory() as session:
            return list(
                (
                    await session.execute(
                        select(PortService)
                        .where(PortService.scan_id == self.scan_id)
                        .order_by(PortService.ip, PortService.port)
                    )
                )
                .scalars()
                .all()
            )

    async def by_port(self) -> dict[tuple[str, int], PortService]:
        return {(r.ip, r.port): r for r in await self.rows()}

    async def tool_runs(self) -> list[ToolRunRecord]:
        async with self.factory() as session:
            return list(
                (
                    await session.execute(
                        select(ToolRunRecord)
                        .where(ToolRunRecord.scan_id == self.scan_id)
                        .order_by(ToolRunRecord.seq)
                    )
                )
                .scalars()
                .all()
            )

    async def scan(self) -> Scan:
        async with self.factory() as session:
            scan = await session.get(Scan, self.scan_id)
            assert scan is not None
            return scan


async def run_ports_step(
    db_engine,
    recon: ReconResult,
    *,
    tools: PortTools,
    options: dict | None = None,
    guard=None,
    hosts=None,
    cancel=None,
    log=None,
    profile: str = "light",
    speed_pps: float = 100,
    allow_private: bool = True,
    authorised: bool = True,
    all_ports_confirmed: bool = False,
    all_ports_authorised: bool | None = None,
    environment: str = "production",
    seq: int = 1,
    **kwargs,
) -> PortsResult:
    """Runs run_ports for a fresh authorised scan and returns what it left
    behind. Exceptions (a cancel) are kept in ``.error``."""
    import sentinel_worker_test_fixture_dir_support as sup
    from sentinel_worker_app.ports_adapter import run_ports

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = log or sup.RecordingLog()
    cancel = cancel or sup.FakeCancel()
    guard = guard or sup.guard_for(hosts or {h.host for h in recon.assets} | {recon.root_domain})
    error = None
    stats = None
    async with factory() as session:
        scan, target = await sup.scan_with_authorisation(
            session,
            options or {"port_scan": True},
            root_domain=recon.root_domain,
            authorised=authorised,
            tools=["port_scan", "all_ports"] if all_ports_confirmed else ["port_scan"],
            all_ports_confirmed=all_ports_confirmed,
            target_environment=environment,
        )
        try:
            stats = await run_ports(
                session,
                scan,
                target,
                recon,
                guard,
                profile,
                speed_pps,
                cancel,
                log,
                seq,
                authorised_by="alice",
                all_ports_authorised=(
                    all_ports_confirmed if all_ports_authorised is None else all_ports_authorised
                ),
                environment=environment,
                allow_private=allow_private,
                tools=tools,
                **kwargs,
            )
        except BaseException as exc:  # noqa: BLE001 — the test inspects it
            error = exc
    return PortsResult(stats, log, scan.id, target.id, factory, error)
