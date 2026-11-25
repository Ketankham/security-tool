"""naabu wrapper: argument list, line parsing, and run_naabu against fake `naabu`
binaries (a Python script earlier on PATH). The real binary is exercised in
test_naabu_integration.py."""

import asyncio
import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest
from sentinel_recon import naabu_wrapper
from sentinel_recon.naabu_wrapper import (
    MAX_OPEN_PORTS,
    SUSPICIOUS_NOTE,
    OpenPort,
    build_args,
    default_timeout_s,
    estimate_seconds,
    parse_line,
    run_naabu,
)
from sentinel_recon.runs import tool_run_from
from sentinel_recon.tooling import MAX_OUTPUT_BYTES


def port_line(port=22, ip="203.0.113.7", **extra):
    return json.dumps(
        {
            "ip": ip,
            "timestamp": "2026-11-25T10:00:00.123456789Z",
            "port": port,
            "protocol": "tcp",
            "tls": False,
            **extra,
        }
    )


# --- build_args -----------------------------------------------------------------


def test_build_args_top_ports_golden():
    assert build_args("203.0.113.7", all_ports=False, pps=100) == [
        "-host", "203.0.113.7",
        "-top-ports", "1000",
        "-scan-type", "c", "-Pn",
        "-rate", "100",
        "-retries", "2",
        "-exclude-cdn", "-cdn", "-verify",
        "-iv", "4",
        "-json", "-duc", "-nc", "-v",
    ]  # fmt: skip


def test_build_args_all_ports_golden():
    assert build_args("203.0.113.7", all_ports=True, pps=100) == [
        "-host", "203.0.113.7",
        "-p", "1-65535",
        "-scan-type", "c", "-Pn",
        "-rate", "100",
        "-retries", "1",
        "-exclude-cdn", "-cdn", "-verify",
        "-iv", "4",
        "-json", "-duc", "-nc", "-v",
    ]  # fmt: skip


def test_build_args_ipv6_literal_asks_for_ip_version_6():
    args = build_args("2001:db8::1", all_ports=False, pps=50)
    assert args[:2] == ["-host", "2001:db8::1"]
    assert args[args.index("-iv") + 1] == "6"


@pytest.mark.parametrize("all_ports", [False, True])
@pytest.mark.parametrize("pps", [1, 50, 100, 200])
def test_build_args_is_connect_scan_with_a_rate_and_never_syn_or_udp(all_ports, pps):
    args = build_args("203.0.113.7", all_ports=all_ports, pps=pps)
    assert args[args.index("-scan-type") + 1] == "c"
    assert "-Pn" in args
    assert args[args.index("-rate") + 1] == str(pps)
    for forbidden in ("s", "S", "syn", "SYN", "-sS", "-sU", "-u", "-udp", "-sn", "-ping"):
        assert forbidden not in args
    assert all(a not in ("-scan-type=s", "-st") for a in args)
    # one scan-type value, and it is the connect scan
    assert args.count("-scan-type") == 1


@pytest.mark.parametrize(
    ("pps", "expected"), [(0, "1"), (-5, "1"), (0.4, "1"), (7.9, "7"), (100.0, "100")]
)
def test_build_args_rate_is_always_a_positive_integer(pps, expected):
    """naabu's -rate 0 is fatal and its default is 1000: always pass a sane rate."""
    args = build_args("203.0.113.7", all_ports=False, pps=pps)
    assert args[args.index("-rate") + 1] == expected


@pytest.mark.parametrize(
    "bad", ["", "example.com", "-oN", "-host", "203.0.113.7 -p 1-65535", "203.0.113.256", "1.2.3"]
)
def test_build_args_refuses_anything_that_is_not_an_ip_address(bad):
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        build_args(bad, all_ports=False, pps=100)


def test_estimate_and_default_timeout_follow_the_documented_formula():
    # top ports: 1000 ports x 2 passes / pps + 5 s; all ports: 65535 / pps + 5 s
    assert estimate_seconds(all_ports=False, pps=100) == 25.0
    assert estimate_seconds(all_ports=True, pps=100) == pytest.approx(65535 / 100 + 5)
    assert default_timeout_s(all_ports=False, pps=100) == 1.5 * 25 + 60
    assert default_timeout_s(all_ports=True, pps=100) == pytest.approx(1.5 * (655.35 + 5) + 60)
    assert default_timeout_s(all_ports=False, pps=0) == 1.5 * (2000 + 5) + 60  # clamped to 1 pps


def test_estimate_matches_scan_options_per_ip_seconds():
    from sentinel_core import scan_options

    est = scan_options.estimate({"port_scan": True, "all_ports": True, "speed": "normal"})
    assert est["port_scan"]["seconds_per_ip"] == int(estimate_seconds(all_ports=False, pps=100))
    assert est["all_ports"]["seconds_per_ip"] == int(estimate_seconds(all_ports=True, pps=100))


# --- parse_line -----------------------------------------------------------------


def test_parse_line_plain():
    assert parse_line(port_line(443, tls=True)) == OpenPort(
        ip="203.0.113.7", port=443, protocol="tcp", host=None, tls=True, cdn=False, cdn_name=None
    )


def test_parse_line_with_host_and_cdn():
    p = parse_line(port_line(80, host="www.example.com", cdn=True, **{"cdn-name": "cloudflare"}))
    assert p is not None
    assert (p.host, p.cdn, p.cdn_name) == ("www.example.com", True, "cloudflare")


def test_parse_line_a_cdn_name_alone_implies_cdn():
    p = parse_line(port_line(80, **{"cdn-name": "akamai"}))
    assert p is not None and p.cdn is True and p.cdn_name == "akamai"


def test_parse_line_tolerates_extra_and_missing_keys():
    assert parse_line('{"ip":"203.0.113.7","port":22}') == OpenPort(ip="203.0.113.7", port=22)
    p = parse_line(port_line(22, brand_new_key={"nested": [1, 2]}, another=None))
    assert p is not None and p.port == 22
    p = parse_line('{"ip":"203.0.113.7","port":22,"protocol":"","tls":"yes","cdn":"true"}')
    assert p is not None and (p.protocol, p.tls, p.cdn) == ("tcp", False, False)


def test_parse_line_accepts_a_port_given_as_a_numeric_string_or_whole_float():
    assert parse_line('{"ip":"1.2.3.4","port":"8080"}') == OpenPort(ip="1.2.3.4", port=8080)
    assert parse_line('{"ip":"1.2.3.4","port":8080.0}') == OpenPort(ip="1.2.3.4", port=8080)


def test_parse_line_surrounding_whitespace_and_carriage_return():
    assert parse_line("  " + port_line(25) + "\r") == OpenPort(ip="203.0.113.7", port=25)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "garbage",
        "[INF] Found 1 ports on host 203.0.113.7 (203.0.113.7)",
        "[DBG] Validated active port 8765 on 127.0.0.1",
        "{",
        "{not json}",
        "[]",
        "[1, 2]",
        '"just a string"',
        "42",
        "null",
        "{}",
        '{"ip":"1.2.3.4"}',
        '{"port":22}',
        '{"ip":"","port":22}',
        '{"ip":5,"port":22}',
        '{"ip":"1.2.3.4","port":0}',
        '{"ip":"1.2.3.4","port":65536}',
        '{"ip":"1.2.3.4","port":-1}',
        '{"ip":"1.2.3.4","port":true}',
        '{"ip":"1.2.3.4","port":"http"}',
        '{"ip":"1.2.3.4","port":22.5}',
        '{"ip":"1.2.3.4","port":null}',
        '{"ip":"1.2.3.4","port":[22]}',
    ],
)
def test_parse_line_returns_none_for_junk(line):
    assert parse_line(line) is None


def test_parse_line_survives_deep_nesting():
    assert parse_line("{" * 100_000) is None
    assert parse_line("[" * 100_000) is None


# --- fake binaries -----------------------------------------------------------------


def install_fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    """A python script called `naabu` first on PATH."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "naabu"
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return script


def alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"  # a zombie is dead; init just has not reaped it


async def wait_dead(*pids: int, within: float = 3.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while loop.time() < deadline:
        if not any(alive(p) for p in pids):
            return True
        await asyncio.sleep(0.05)
    return False


async def wait_for_file(path: Path, within: float = 5.0) -> str:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while loop.time() < deadline:
        if path.exists() and path.read_text().strip():
            return path.read_text()
        await asyncio.sleep(0.05)
    raise AssertionError(f"{path} never appeared")


HANG_WITH_CHILD = """
    import os, subprocess, time
    child = subprocess.Popen(["sleep", "300"])
    open({pids!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
    time.sleep(300)
"""


async def test_canned_output_is_parsed_and_the_args_are_build_args(tmp_path, monkeypatch):
    argv_file = tmp_path / "argv.json"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import json, sys
        open({str(argv_file)!r}, "w").write(json.dumps(sys.argv[1:]))
        sys.stderr.write("[WRN] UI Dashboard is disabled\\n")
        print("[DBG] Validated active port 22 on 203.0.113.7")
        print({port_line(22)!r})
        print("")
        print("garbage line")
        print({port_line(443, tls=True, host="www.example.com")!r})
        print({port_line(22)!r})  # duplicate: naabu -verify can print a port twice
        print("[INF] Found 2 ports on host 203.0.113.7 (203.0.113.7)")
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    assert run.result.ran and run.result.returncode == 0
    assert [(p.ip, p.port, p.tls) for p in run.ports] == [
        ("203.0.113.7", 22, False),
        ("203.0.113.7", 443, True),
    ]
    assert run.stop_reason is None and run.error is None
    assert run.suspicious is False and run.note is None
    assert json.loads(argv_file.read_text()) == build_args("203.0.113.7", all_ports=False, pps=100)
    # the unparseable lines are still in the stored output
    assert "garbage line" in run.result.stdout
    assert (
        tool_run_from("naabu", run.result, binary="naabu", version=None, results_count=2).status
        == "ok"
    )


async def test_on_port_is_called_once_per_new_port_and_its_failure_is_ignored(
    tmp_path, monkeypatch
):
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        print({port_line(22)!r})
        print({port_line(80)!r})
        print({port_line(22)!r})
        """,
    )
    seen: list[int] = []

    def on_port(p: OpenPort) -> None:
        seen.append(p.port)
        if p.port == 22:
            raise RuntimeError("a logging hiccup")

    run = await run_naabu("203.0.113.7", all_ports=False, pps=100, on_port=on_port)
    assert seen == [22, 80]
    assert [p.port for p in run.ports] == [22, 80]
    assert run.stop_reason is None and run.result.returncode == 0


async def test_binary_missing_is_reported_not_raised(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert await naabu_wrapper.is_available() is False
    assert await naabu_wrapper.version() is None
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    assert run.result.ran is False
    assert run.ports == [] and run.stop_reason is None and run.error is None
    tool_run = tool_run_from("naabu", run.result, binary="naabu", version=None, results_count=0)
    assert tool_run.status == "not_installed"


async def test_is_available_is_true_when_a_binary_is_on_path(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "print('hi')\n")
    assert await naabu_wrapper.is_available() is True


async def test_an_invalid_address_is_a_value_error_and_nothing_starts(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    install_fake(tmp_path, monkeypatch, f"open({str(marker)!r}, 'w').write('x')\n")
    with pytest.raises(ValueError):
        await run_naabu("not-an-ip", all_ports=False, pps=100)
    assert not marker.exists()


async def test_exit_non_zero_keeps_ports_and_reports_the_fatal_message(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import sys
        print({port_line(22)!r})
        sys.stderr.write("[FTL] Program exiting: cause=\\"cannot be zero\\" chain=\\"rate\\"\\n")
        sys.exit(1)
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    assert run.result.returncode == 1
    assert [p.port for p in run.ports] == [22]
    assert run.stop_reason is None
    assert run.error is not None
    assert run.error.startswith("naabu exited with code 1: Program exiting")
    assert (
        tool_run_from("naabu", run.result, binary="naabu", version=None, results_count=1).status
        == "failed"
    )


async def test_exit_non_zero_without_a_message(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "import sys\nsys.exit(3)\n")
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    assert run.error == "naabu exited with code 3" and run.ports == []


async def test_timeout_keeps_the_ports_found_and_kills_everything(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, sys, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        print({port_line(22)!r}, flush=True)
        print({port_line(80)!r}, flush=True)
        time.sleep(300)
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100, timeout_s=1.5)
    assert run.result.timed_out is True
    assert run.stop_reason == "timed out"
    assert run.error is None  # we killed it; it did not fail on its own
    assert [p.port for p in run.ports] == [22, 80]  # what it printed first is kept
    me, child = (int(x) for x in pids.read_text().split())
    assert await wait_dead(me, child)
    assert (
        tool_run_from("naabu", run.result, binary="naabu", version=None, results_count=2).status
        == "timed_out"
    )


async def test_cancel_check_stops_naabu_and_everything_it_started(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(tmp_path, monkeypatch, HANG_WITH_CHILD.format(pids=str(pids)))

    async def cancel_check():
        return "alice" if pids.exists() and pids.read_text().strip() else None

    run = await run_naabu("203.0.113.7", all_ports=False, pps=100, cancel_check=cancel_check)
    assert run.result.cancelled is True and run.result.cancelled_by == "alice"
    assert run.stop_reason == "cancelled"
    me, child = (int(x) for x in pids.read_text().split())
    assert await wait_dead(me, child)
    tool_run = tool_run_from("naabu", run.result, binary="naabu", version=None, results_count=0)
    assert (tool_run.status, tool_run.skip_reason) == ("cancelled", "Cancelled by alice")


async def test_cancelling_the_awaiting_task_kills_the_process_group(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(tmp_path, monkeypatch, HANG_WITH_CHILD.format(pids=str(pids)))
    task = asyncio.create_task(run_naabu("203.0.113.7", all_ports=False, pps=100, timeout_s=120))
    me, child = (int(x) for x in (await wait_for_file(pids)).split())
    assert alive(me) and alive(child)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await wait_dead(me, child)


async def test_default_timeout_is_used_when_none_is_given(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "print('x')\n")
    seen = {}

    async def fake_run_tool(binary, args, **kwargs):
        seen.update(kwargs)
        from sentinel_recon.tooling import ToolRunResult

        return ToolRunResult(ran=True, returncode=0)

    monkeypatch.setattr(naabu_wrapper, "run_tool", fake_run_tool)
    await run_naabu("203.0.113.7", all_ports=True, pps=100)
    assert seen["timeout_s"] == default_timeout_s(all_ports=True, pps=100)
    await run_naabu("203.0.113.7", all_ports=False, pps=100, timeout_s=7)
    assert seen["timeout_s"] == 7
    assert set(seen["env"]) == {"HOME", "XDG_CONFIG_HOME"}


async def test_huge_output_is_stored_truncated_but_every_port_is_seen(tmp_path, monkeypatch):
    # ~4 MB of banner/debug noise around a handful of real ports
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import sys
        noise = "[DBG] " + "x" * 200 + "\\n"
        for _ in range(10000):
            sys.stdout.write(noise)
        print({port_line(22)!r})
        for _ in range(10000):
            sys.stdout.write(noise)
        print({port_line(443)!r})
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100, timeout_s=30)
    assert len(run.result.stdout) <= MAX_OUTPUT_BYTES < 4_000_000
    assert [p.port for p in run.ports] == [22, 443]
    assert run.stop_reason is None and run.suspicious is False


async def test_more_than_100_open_ports_is_flagged_suspicious(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        for port in range(1, 102):
            print('{{"ip":"203.0.113.7","port":%d,"protocol":"tcp","tls":false}}' % port)
        print({port_line(101)!r})  # a duplicate does not count twice
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    assert len(run.ports) == 101
    assert run.suspicious is True
    assert run.note == SUSPICIOUS_NOTE == "ports appear open everywhere (firewall/proxy?)"


async def test_exactly_100_open_ports_is_not_suspicious(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        """
        for port in range(1, 101):
            print('{"ip":"203.0.113.7","port":%d,"protocol":"tcp","tls":false}' % port)
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    assert len(run.ports) == 100 and run.suspicious is False


async def test_a_runaway_port_count_is_stopped_and_flagged(tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, sys, time
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        for port in range(1, 65536):
            sys.stdout.write('{{"ip":"203.0.113.7","port":%d,"protocol":"tcp"}}\\n' % port)
        sys.stdout.flush()
        time.sleep(300)
        """,
    )
    run = await run_naabu("203.0.113.7", all_ports=True, pps=100, timeout_s=30)
    assert run.stop_reason == naabu_wrapper.TOO_MANY_PORTS
    assert run.result.stopped_reason is not None and run.result.timed_out is False
    assert len(run.ports) == MAX_OPEN_PORTS + 1
    assert run.suspicious is True
    assert await wait_dead(int(pidfile.read_text()))
    assert (
        tool_run_from("naabu", run.result, binary="naabu", version=None, results_count=1).status
        == "stopped"
    )


async def test_naabu_gets_a_private_home_and_it_is_removed_afterwards(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        """
        import os, sys
        sys.stderr.write("HOME=%s\\nXDG=%s\\nCWD=%s\\n" % (
            os.environ["HOME"], os.environ["XDG_CONFIG_HOME"], os.getcwd()))
        os.makedirs(os.environ["HOME"] + "/.config/naabu", exist_ok=True)
        os.makedirs(os.environ["HOME"] + "/.config/uncover", exist_ok=True)
        open("scratch.txt", "w").write("x")
        """,
    )
    monkeypatch.setenv("HOME", "/nonexistent-real-home")
    run = await run_naabu("203.0.113.7", all_ports=False, pps=100)
    lines = dict(line.split("=", 1) for line in run.result.stderr.split())
    home = lines["HOME"]
    assert home != "/nonexistent-real-home"
    assert lines["XDG"] == f"{home}/cfg"
    assert lines["CWD"] == home
    assert not Path(home).exists()


# --- version -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("[INF] Current Version: 2.7.0\\n", "v2.7.0"),
        ("Current Version: v2.7.0\\n", "v2.7.0"),
        ("naabu 2.8.1\\n", "v2.8.1"),
        ("no version here\\n", None),
        ("", None),
    ],
)
async def test_version_parses_the_banner(tmp_path, monkeypatch, output, expected):
    install_fake(tmp_path, monkeypatch, f"import sys\nsys.stderr.write('{output}')\n")
    assert await naabu_wrapper.version() == expected


async def test_version_asks_with_the_update_check_off(tmp_path, monkeypatch):
    argv_file = tmp_path / "argv.json"
    install_fake(
        tmp_path,
        monkeypatch,
        f"import json, sys\nopen({str(argv_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n",
    )
    await naabu_wrapper.version()
    assert json.loads(argv_file.read_text()) == ["-version", "-duc", "-nc"]


async def test_version_never_raises(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "import sys\nsys.stderr.write('boom')\nsys.exit(3)\n")
    assert await naabu_wrapper.version() is None

    async def explode(*a, **kw):
        raise OSError("exec failed")

    monkeypatch.setattr(naabu_wrapper, "run_tool", explode)
    assert await naabu_wrapper.version() is None


async def test_version_survives_a_hanging_binary(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "import time\ntime.sleep(60)\n")
    real_run_tool = naabu_wrapper.run_tool

    async def quick(binary, args, *, timeout_s=5.0, **kw):
        return await real_run_tool(binary, args, timeout_s=0.5, **kw)

    monkeypatch.setattr(naabu_wrapper, "run_tool", quick)
    assert await naabu_wrapper.version() is None
