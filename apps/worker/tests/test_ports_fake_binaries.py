"""The port scanning step through the REAL wrappers, with fake ``naabu`` and
``nmap`` scripts first on PATH: the exact arguments they are started with, a
missing binary, a hung binary that is cancelled (and not left running), a flood
of output, and secret-looking script output that must not reach the database."""

# ruff: noqa: E501 -- the XML fixtures keep nmap's own long lines

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import sentinel_worker_test_fixture_dir_support as sup
import sentinel_worker_test_fixture_port_support as ps
from sentinel_core.redact import REDACTED
from sentinel_worker_app.cancel import ScanCancelled
from sentinel_worker_app.ports_adapter import PortTools

PUBLIC_1 = "34.120.0.7"
BEARER = "Zx9Qk2LmPv7RtW4yUb8N"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"

FAKE_NAABU = """
    import json, os, sys, time
    args = sys.argv[1:]
    if "-version" in args:
        sys.stderr.write("[INF] Current Version: 2.7.0\\n")
        sys.exit(0)
    capture = os.environ.get("FAKE_NAABU_CAPTURE")
    if capture:
        with open(capture, "a") as f:
            f.write(json.dumps(args) + "\\n")
        with open(capture + ".pid", "a") as f:
            f.write(str(os.getpid()) + "\\n")
    ip = args[args.index("-host") + 1]
    mode = os.environ.get("FAKE_NAABU_MODE", "ports")
    if mode == "hang":
        print(json.dumps({"ip": ip, "port": 443, "protocol": "tcp", "tls": False}), flush=True)
        time.sleep(120)
    if mode == "flood":
        for i in range(60000):
            print(json.dumps({"ip": ip, "port": 1 + (i % 60), "protocol": "tcp", "tls": False, "pad": "x" * 100}), flush=True)
        sys.exit(0)
    for port in [int(p) for p in os.environ.get("FAKE_NAABU_PORTS", "22,443").split(",") if p]:
        print(json.dumps({"ip": ip, "port": port, "protocol": "tcp", "tls": False}), flush=True)
"""

NMAP_XML = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.93"><host><address addr="{PUBLIC_1}" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/><script id="banner" output="SSH-2.0-OpenSSH_8.9&#xa;Authorization: Bearer {BEARER}&#xa;{JWT}"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/></port>
</ports></host></nmaprun>
"""

FAKE_NMAP = f"""
    import json, os, sys, time
    args = sys.argv[1:]
    if "--version" in args:
        print("Nmap version 7.93 ( https://nmap.org )")
        sys.exit(0)
    capture = os.environ.get("FAKE_NMAP_CAPTURE")
    if capture:
        with open(capture, "w") as f:
            json.dump(args, f)
        with open(capture + ".pid", "w") as f:
            f.write(str(os.getpid()))
    if os.environ.get("FAKE_NMAP_MODE") == "hang":
        time.sleep(120)
    open(args[args.index("-oN") + 1], "w").write("Nmap scan report\\n|_banner: Authorization: Bearer {BEARER}\\n{JWT}\\n")
    sys.stdout.write({NMAP_XML!r})
"""


def recon(*ips: str):
    return ps.recon_ips(("acme.test", list(ips)))


def captured(path: Path) -> list[list[str]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


async def test_the_real_wrappers_start_the_tools_with_a_rate_and_connect_scans_only(
    db_engine, tmp_path, monkeypatch
):
    ps.install_fake_binary(tmp_path, monkeypatch, "naabu", FAKE_NAABU)
    ps.install_fake_binary(tmp_path, monkeypatch, "nmap", FAKE_NMAP)
    naabu_log, nmap_log = tmp_path / "naabu.json", tmp_path / "nmap.json"
    monkeypatch.setenv("FAKE_NAABU_CAPTURE", str(naabu_log))
    monkeypatch.setenv("FAKE_NMAP_CAPTURE", str(nmap_log))

    result = await ps.run_ports_step(
        db_engine,
        recon(PUBLIC_1),
        tools=PortTools(),  # the real wrappers, the fake binaries
        profile="full",
        speed_pps=50,
    )

    assert result.error is None
    (naabu_args,) = captured(naabu_log)
    assert naabu_args[naabu_args.index("-host") + 1] == PUBLIC_1
    assert naabu_args[naabu_args.index("-scan-type") + 1] == "c"
    assert naabu_args[naabu_args.index("-rate") + 1] == "50"
    assert "-Pn" in naabu_args and "-top-ports" in naabu_args and "-p" not in naabu_args
    nmap_args = json.loads(nmap_log.read_text())
    assert "-sT" in nmap_args and "--unprivileged" in nmap_args
    assert nmap_args[nmap_args.index("--max-rate") + 1] == "50"
    assert nmap_args[nmap_args.index("--script") + 1] == "default and safe and not http-*"
    assert nmap_args[nmap_args.index("-p") + 1] == "22,443"
    for forbidden in ("-sS", "-sU", "-O", "-A", "-sC", "-sn", "-PS", "-PU"):
        assert forbidden not in naabu_args + nmap_args

    rows = await result.by_port()
    assert (
        rows[(PUBLIC_1, 22)].product == "OpenSSH" and rows[(PUBLIC_1, 22)].confidence == "detected"
    )
    runs = await result.tool_runs()
    assert [(r.tool, r.status, r.version) for r in runs] == [
        ("naabu", "ok", "v2.7.0"),
        ("nmap", "ok", "7.93"),
    ]
    assert result.stats.web_seeds == []  # 443 is a standard web port


async def test_secrets_in_real_nmap_output_never_reach_the_database_or_the_activity_log(
    db_engine, tmp_path, monkeypatch
):
    ps.install_fake_binary(tmp_path, monkeypatch, "naabu", FAKE_NAABU)
    ps.install_fake_binary(tmp_path, monkeypatch, "nmap", FAKE_NMAP)
    result = await ps.run_ports_step(db_engine, recon(PUBLIC_1), tools=PortTools(), profile="full")
    stored = await sup.everything_stored(db_engine)
    assert BEARER not in stored and JWT not in stored
    rows = await result.by_port()
    banner = rows[(PUBLIC_1, 22)].scripts["banner"]
    assert banner.startswith("SSH-2.0-OpenSSH_8.9") and REDACTED in banner
    runs = await result.tool_runs()
    nmap_run = runs[1]
    assert REDACTED in nmap_run.extra_output and BEARER not in nmap_run.stdout
    assert nmap_run.extra_output_label == "nmap normal output (-oN)"
    assert not any(BEARER in m or JWT in m for m in result.log.messages)


async def test_a_missing_naabu_skips_the_step_and_a_missing_nmap_falls_back(
    db_engine, tmp_path, monkeypatch
):
    # nothing on PATH: neither tool exists
    ps.no_binaries_on_path(tmp_path, monkeypatch)
    result = await ps.run_ports_step(db_engine, recon(PUBLIC_1), tools=PortTools(), profile="full")
    assert result.error is None and await result.rows() == []
    (run,) = await result.tool_runs()
    assert (run.tool, run.status) == ("naabu", "not_installed")
    scan = await result.scan()
    assert scan.is_degraded and any("naabu is not installed" in r for r in scan.degraded_reasons)

    # naabu present, nmap not: naabu-only rows, one note, one skipped run
    ps.install_fake_binary(tmp_path, monkeypatch, "naabu", FAKE_NAABU)
    second = await ps.run_ports_step(db_engine, recon(PUBLIC_1), tools=PortTools(), profile="full")
    note = "nmap not installed — services named from port numbers (unverified)"
    assert second.log.messages.count(note) == 1
    assert [(r.tool, r.status) for r in await second.tool_runs()] == [
        ("nmap", "skipped"),
        ("naabu", "ok"),
    ]
    assert {r.service for r in await second.rows()} == {"ssh", "https"}
    assert {r.confidence for r in await second.rows()} == {"port_guess"}


async def test_cancelling_while_naabu_hangs_kills_it_and_ends_the_step(
    db_engine, tmp_path, monkeypatch
):
    ps.install_fake_binary(tmp_path, monkeypatch, "naabu", FAKE_NAABU)
    monkeypatch.setenv("FAKE_NAABU_MODE", "hang")
    capture = tmp_path / "naabu.json"
    monkeypatch.setenv("FAKE_NAABU_CAPTURE", str(capture))
    cancel = sup.FakeCancel()

    async def press_cancel():
        pid_file = Path(f"{capture}.pid")
        for _ in range(100):
            if pid_file.exists() and pid_file.read_text().strip():
                break
            await asyncio.sleep(0.05)
        cancel.by = "dana"

    presser = asyncio.ensure_future(press_cancel())
    result = await asyncio.wait_for(
        ps.run_ports_step(db_engine, recon(PUBLIC_1), tools=PortTools(), cancel=cancel), timeout=30
    )
    await presser
    assert isinstance(result.error, ScanCancelled) and result.error.by == "dana"
    (run,) = await result.tool_runs()
    assert (run.status, run.skip_reason) == ("cancelled", "Cancelled by dana")
    pid = int(Path(f"{capture}.pid").read_text().split()[0])
    deadline = asyncio.get_running_loop().time() + 5
    while alive(pid) and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.05)
    assert not alive(pid)
    assert [(r.port) for r in await result.rows()] == [443]  # the port it reported first is kept


async def test_cancelling_while_nmap_hangs_kills_it(db_engine, tmp_path, monkeypatch):
    ps.install_fake_binary(tmp_path, monkeypatch, "naabu", FAKE_NAABU)
    ps.install_fake_binary(tmp_path, monkeypatch, "nmap", FAKE_NMAP)
    monkeypatch.setenv("FAKE_NMAP_MODE", "hang")
    capture = tmp_path / "nmap.json"
    monkeypatch.setenv("FAKE_NMAP_CAPTURE", str(capture))
    cancel = sup.FakeCancel()

    async def press_cancel():
        pid_file = Path(f"{capture}.pid")
        for _ in range(200):
            if pid_file.exists() and pid_file.read_text().strip():
                break
            await asyncio.sleep(0.05)
        cancel.by = "dana"

    presser = asyncio.ensure_future(press_cancel())
    result = await asyncio.wait_for(
        ps.run_ports_step(
            db_engine, recon(PUBLIC_1), tools=PortTools(), cancel=cancel, profile="full"
        ),
        timeout=30,
    )
    await presser
    assert isinstance(result.error, ScanCancelled)
    assert [(r.tool, r.status) for r in await result.tool_runs()] == [
        ("naabu", "ok"),
        ("nmap", "cancelled"),
    ]
    pid = int(Path(f"{capture}.pid").read_text())
    deadline = asyncio.get_running_loop().time() + 5
    while alive(pid) and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.05)
    assert not alive(pid)


async def test_a_flood_of_output_is_stored_truncated_and_the_scan_goes_on(
    db_engine, tmp_path, monkeypatch
):
    ps.install_fake_binary(tmp_path, monkeypatch, "naabu", FAKE_NAABU)
    monkeypatch.setenv("FAKE_NAABU_MODE", "flood")
    result = await ps.run_ports_step(db_engine, recon(PUBLIC_1), tools=PortTools())
    assert result.error is None
    (run,) = await result.tool_runs()
    assert run.stdout_truncated is True and len(run.stdout) <= 512_000
    assert len(await result.rows()) == 60  # only 60 distinct ports in the flood
