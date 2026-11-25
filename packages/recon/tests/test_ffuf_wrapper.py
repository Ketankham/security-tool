"""ffuf wrapper: argument list, line parsing, stop reasons, and run_ffuf against
fake `ffuf` binaries (a Python script earlier on PATH). The real binary is
exercised in test_ffuf_integration.py."""

import asyncio
import base64
import inspect
import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest
from sentinel_core.http_engine import USER_AGENT, HttpEngine
from sentinel_recon import ffuf_wrapper
from sentinel_recon.dir_hits import BackpressureMonitor
from sentinel_recon.ffuf_wrapper import (
    MAX_HITS,
    FfufHit,
    build_args,
    parse_line,
    run_ffuf,
    stop_reason_from_stderr,
)
from sentinel_recon.runs import tool_run_from
from sentinel_recon.tooling import MAX_OUTPUT_BYTES


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def hit_line(path="admin", status=200, **extra):
    doc = {
        "input": {"FFUFHASH": "abc", "FUZZ": b64(path)},
        "position": 1,
        "status": status,
        "length": 10,
        "words": 2,
        "lines": 1,
        "content-type": "text/html",
        "redirectlocation": "",
        "url": f"http://127.0.0.1:1/{path}",
        "duration": 123456,
        "host": "127.0.0.1:1",
        **extra,
    }
    return json.dumps(doc)


# --- build_args -----------------------------------------------------------------


def test_build_args_golden():
    assert build_args(
        "https://203.0.113.9:8443",
        "/tmp/w/paths.txt",
        ["sentinelcal1", "sentinelcal2", "sentinelcal3/"],
        50,
        900,
        host_header="shop.example:8443",
        sni="shop.example",
    ) == [
        "-u", "https://203.0.113.9:8443/FUZZ",
        "-w", "/tmp/w/paths.txt:FUZZ",
        "-H", f"User-Agent: {USER_AGENT}",
        "-H", "Host: shop.example:8443",
        "-sni", "shop.example",
        "-ac", "-acc", "sentinelcal1", "-acc", "sentinelcal2", "-acc", "sentinelcal3/",
        "-mc", "all", "-fc", "404", "-t", "2", "-rate", "50",
        "-timeout", "10", "-maxtime", "900", "-sa",
        "-json", "-s", "-noninteractive",
    ]  # fmt: skip


def test_build_args_without_host_header_or_sni():
    args = build_args("http://127.0.0.1:80", "w.txt", ["a", "b", "c"], 10, 60)
    assert args == [
        "-u", "http://127.0.0.1:80/FUZZ",
        "-w", "w.txt:FUZZ",
        "-H", f"User-Agent: {USER_AGENT}",
        "-ac", "-acc", "a", "-acc", "b", "-acc", "c",
        "-mc", "all", "-fc", "404", "-t", "2", "-rate", "10",
        "-timeout", "10", "-maxtime", "60", "-sa",
        "-json", "-s", "-noninteractive",
    ]  # fmt: skip
    assert "-sni" not in args and "Host:" not in " ".join(args)


@pytest.mark.parametrize(("rps", "expected"), [(0, "1"), (0.4, "1"), (7.9, "7"), (250, "250")])
def test_build_args_rate_is_a_positive_integer(rps, expected):
    args = build_args("http://h", "w", ["a", "b", "c"], rps, 60)
    assert args[args.index("-rate") + 1] == expected


def test_build_args_never_contains_a_forbidden_flag():
    forbidden = {"-recursion", "-r", "-X", "-d", "-input-cmd", "-preflight", "-od", "-audit-log"}
    for host, sni in ((None, None), ("h:1", "h")):
        args = build_args("https://1.2.3.4", "w", ["a", "b", "c"], 100, 600, host, sni)
        assert not forbidden & set(args)
        assert not any(a.startswith(("-recursion", "-od", "-audit")) for a in args)
        assert "-ac" in args
        assert args.count("-acc") >= 3
        assert "-sa" in args and "-maxtime" in args and "-rate" in args


def test_build_args_does_not_double_the_slash():
    assert build_args("http://h:80/", "w", ["a"], 1, 1)[1] == "http://h:80/FUZZ"


def test_user_agent_constant_is_the_http_engines_default():
    default = inspect.signature(HttpEngine.__init__).parameters["user_agent"].default
    assert default == USER_AGENT
    assert USER_AGENT.startswith("SentinelScanner/")


# --- parse_line -----------------------------------------------------------------


def test_parse_line_decodes_the_fuzz_input():
    h = parse_line(hit_line(".git/HEAD", 200, redirectlocation="/x?y=1", **{"content-type": "a/b"}))
    assert h == FfufHit(
        path=".git/HEAD",
        status=200,
        length=10,
        words=2,
        lines=1,
        content_type="a/b",
        redirect="/x?y=1",
        url="http://127.0.0.1:1/.git/HEAD",
    )


def test_parse_line_handles_unicode_and_padding():
    h = parse_line(hit_line("café/ü"))
    assert h is not None and h.path == "café/ü"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "not json",
        "[]",
        "[1,2]",
        '"x"',
        "null",
        "{",
        '{"status": 200}',  # no input
        '{"input": {}, "status": 200}',  # no FUZZ
        '{"input": {"FUZZ": ""}, "status": 200}',
        '{"input": {"FUZZ": 5}, "status": 200}',
        '{"input": "x", "status": 200}',
        '{"input": {"FUZZ": "!!!notbase64!!!"}, "status": 200}',
        '{"input": {"FUZZ": "YWRtaW4="}}',  # no status
        '{"input": {"FUZZ": "YWRtaW4="}, "status": "200"}',
        '{"input": {"FUZZ": "YWRtaW4="}, "status": true}',
        "::ffuf progress::",
        "\x00\x01",
    ],
)
def test_parse_line_returns_none_for_malformed_lines(line):
    assert parse_line(line) is None


def test_parse_line_tolerates_missing_and_odd_optional_keys():
    h = parse_line('{"input": {"FUZZ": "YWRtaW4="}, "status": 301}')
    assert h == FfufHit(path="admin", status=301)
    h = parse_line(
        '{"input": {"FUZZ": "YWRtaW4="}, "status": 200, "length": "12", "words": null, '
        '"lines": [], "content-type": 5, "redirectlocation": null}'
    )
    assert h is not None
    assert (h.length, h.words, h.lines, h.content_type, h.redirect) == (12, 0, 0, "", "")


def test_parse_line_survives_deep_nesting():
    assert parse_line("{" * 100_000) is None
    assert parse_line("[" * 100_000) is None


# --- stop_reason_from_stderr ------------------------------------------------------


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("Getting an unusual amount of 429 responses, exiting.\n", "rate limited (429)"),
        (
            "Getting an unusual amount of 403 responses, exiting.\n",
            "the host answered 403 to almost everything",
        ),
        ("Receiving spurious errors, exiting.\n", "too many connection errors"),
        (
            "Maximum running time for entire process reached, exiting.\n",
            "time limit reached (partial results)",
        ),
        ("", None),
        ("2024/01/01 something else\n", None),
    ],
)
def test_stop_reason_from_stderr(stderr, expected):
    assert stop_reason_from_stderr(stderr) == expected


def test_stop_reason_prefers_429_when_several_messages_appear():
    both = (
        "Maximum running time for entire process reached, exiting.\n"
        "Getting an unusual amount of 429 responses, exiting.\n"
    )
    assert stop_reason_from_stderr(both) == "rate limited (429)"


# --- fake binaries ---------------------------------------------------------------------


def install_fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    """A python script called `ffuf` first on PATH."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "ffuf"
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


async def test_canned_output_is_parsed_and_stderr_stop_is_reported(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import sys
        print({hit_line(".env", 200)!r})
        print("garbage line")
        print("")
        print({hit_line("admin", 301, redirectlocation="/admin/")!r})
        sys.stderr.write("Getting an unusual amount of 429 responses, exiting.\\n")
        """,
    )
    run = await run_ffuf(["-u", "x"], timeout_s=10)
    assert run.result.ran and run.result.returncode == 0
    assert [(h.path, h.status) for h in run.hits] == [(".env", 200), ("admin", 301)]
    assert run.hits[1].redirect == "/admin/"
    assert run.stop_reason == "rate limited (429)"
    # the unparseable lines are still in the stored output
    assert "garbage line" in run.result.stdout
    assert (
        tool_run_from("ffuf", run.result, binary="ffuf", version="v2.3.0", results_count=2).status
        == "ok"
    )


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("Getting an unusual amount of 429 responses, exiting.", "rate limited (429)"),
        (
            "Getting an unusual amount of 403 responses, exiting.",
            "the host answered 403 to almost everything",
        ),
        ("Receiving spurious errors, exiting.", "too many connection errors"),
        (
            "Maximum running time for entire process reached, exiting.",
            "time limit reached (partial results)",
        ),
    ],
)
async def test_each_stderr_stop_message_gives_its_reason(tmp_path, monkeypatch, message, reason):
    install_fake(tmp_path, monkeypatch, f"import sys\nsys.stderr.write({message + chr(10)!r})\n")
    run = await run_ffuf([], timeout_s=10)
    assert run.stop_reason == reason
    assert run.hits == []


async def test_clean_finish_has_no_stop_reason(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, f"print({hit_line()!r})\n")
    run = await run_ffuf([], timeout_s=10)
    assert run.stop_reason is None and len(run.hits) == 1


async def test_binary_missing_is_reported_not_raised(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    run = await run_ffuf(["-u", "x"], timeout_s=5)
    assert run.result.ran is False
    assert run.hits == [] and run.stop_reason is None
    tool_run = tool_run_from("ffuf", run.result, binary="ffuf", version=None, results_count=0)
    assert tool_run.status == "not_installed"
    monkeypatch.setattr(ffuf_wrapper, "VERSION_FILE", tmp_path / "nope.version")
    assert await ffuf_wrapper.version() is None


async def test_huge_output_is_stored_truncated_but_every_hit_is_seen(tmp_path, monkeypatch):
    # ~3.2 MB of hit lines
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import sys
        line = {hit_line("a" * 100)!r} + "\\n"
        for _ in range(15000):
            sys.stdout.write(line)
        """,
    )
    run = await run_ffuf([], timeout_s=30)
    assert len(run.result.stdout) <= MAX_OUTPUT_BYTES < 15000 * 250
    assert len(run.hits) == 15000
    assert run.stop_reason is None


async def test_runaway_hit_count_is_stopped(tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, sys
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        line = '{{"input":{{"FUZZ":"YQ=="}},"status":200}}\\n'
        while True:
            sys.stdout.write(line * 1000)
            sys.stdout.flush()
        """,
    )
    run = await run_ffuf([], timeout_s=30)
    assert run.stop_reason == ffuf_wrapper.TOO_MANY_HITS
    assert MAX_HITS <= len(run.hits) < MAX_HITS + 5000
    assert run.result.stopped_reason is not None
    assert await wait_dead(int(pidfile.read_text()))


async def test_timeout_kills_ffuf_and_its_children(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, sys, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        print({hit_line("early")!r}, flush=True)
        time.sleep(300)
        """,
    )
    run = await run_ffuf([], timeout_s=1.0)
    assert run.result.timed_out is True
    assert run.stop_reason == "timed out"
    assert [h.path for h in run.hits] == ["early"]  # what it printed first is kept
    me, child = (int(x) for x in pids.read_text().split())
    assert await wait_dead(me, child)
    assert (
        tool_run_from("ffuf", run.result, binary="ffuf", version=None, results_count=1).status
        == "timed_out"
    )


async def test_cancel_check_stops_ffuf_and_everything_it_started(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        time.sleep(300)
        """,
    )

    async def cancel_check():
        return "alice" if pids.exists() and pids.read_text().strip() else None

    run = await run_ffuf([], timeout_s=60, cancel_check=cancel_check)
    assert run.result.cancelled is True and run.result.cancelled_by == "alice"
    assert run.stop_reason == "cancelled"
    me, child = (int(x) for x in pids.read_text().split())
    assert await wait_dead(me, child)
    tool_run = tool_run_from("ffuf", run.result, binary="ffuf", version=None, results_count=0)
    assert (tool_run.status, tool_run.skip_reason) == ("cancelled", "Cancelled by alice")


async def test_cancelling_the_awaiting_task_kills_the_process_group(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        time.sleep(300)
        """,
    )
    task = asyncio.create_task(run_ffuf([], timeout_s=120))
    me, child = (int(x) for x in (await wait_for_file(pids)).split())
    assert alive(me) and alive(child)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await wait_dead(me, child)


async def test_backpressure_callback_kills_ffuf_and_says_why(tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, sys, time
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        for i in range(10000):
            print({hit_line("p", 429)!r}, flush=True)
            time.sleep(0.01)
        """,
    )
    monitor = BackpressureMonitor()
    seen: list[int] = []

    def on_hit(h: FfufHit) -> bool:
        seen.append(h.status)
        return monitor.observe(h.status)

    run = await run_ffuf([], timeout_s=30, on_hit=on_hit, stop_hint=lambda: monitor.reason)
    assert seen == [429] * 5
    assert len(run.hits) == 5
    assert run.stop_reason and "pushed back" in run.stop_reason
    assert run.result.stopped_reason is not None
    assert await wait_dead(int(pidfile.read_text()))
    tool_run = tool_run_from("ffuf", run.result, binary="ffuf", version=None, results_count=5)
    assert tool_run.status == "stopped"


async def test_a_false_callback_without_a_hint_uses_the_generic_reason(tmp_path, monkeypatch):
    install_fake(
        tmp_path, monkeypatch, f"import time\nprint({hit_line()!r}, flush=True)\ntime.sleep(60)\n"
    )
    run = await run_ffuf([], timeout_s=30, on_hit=lambda h: False)
    assert run.stop_reason == ffuf_wrapper.STOPPED_BY_FILTER


async def test_a_raising_callback_stops_ffuf_fail_closed(tmp_path, monkeypatch):
    install_fake(
        tmp_path, monkeypatch, f"import time\nprint({hit_line()!r}, flush=True)\ntime.sleep(60)\n"
    )

    def boom(h: FfufHit) -> bool:
        raise RuntimeError("bug")

    run = await run_ffuf([], timeout_s=30, on_hit=boom)
    assert run.stop_reason and "output filter failed" in run.stop_reason
    assert run.result.timed_out is False


async def test_a_broken_stop_hint_never_breaks_the_run(tmp_path, monkeypatch):
    install_fake(
        tmp_path, monkeypatch, f"import time\nprint({hit_line()!r}, flush=True)\ntime.sleep(60)\n"
    )

    def bad_hint() -> str | None:
        raise ValueError("x")

    run = await run_ffuf([], timeout_s=30, on_hit=lambda h: False, stop_hint=bad_hint)
    assert run.stop_reason == ffuf_wrapper.STOPPED_BY_FILTER


async def test_ffuf_gets_a_private_home_and_it_is_removed_afterwards(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        """
        import os, sys
        sys.stderr.write("HOME=%s\\nXDG=%s\\nCWD=%s\\n" % (
            os.environ["HOME"], os.environ["XDG_CONFIG_HOME"], os.getcwd()))
        os.makedirs(os.environ["XDG_CONFIG_HOME"] + "/ffuf", exist_ok=True)
        open("scratch.txt", "w").write("x")
        """,
    )
    monkeypatch.setenv("HOME", "/nonexistent-real-home")
    run = await run_ffuf([], timeout_s=10)
    lines = dict(line.split("=", 1) for line in run.result.stderr.split())
    home = lines["HOME"]
    assert home != "/nonexistent-real-home"
    assert lines["XDG"] == f"{home}/cfg"
    assert lines["CWD"] == home
    assert not Path(home).exists()


async def test_a_caller_supplied_workdir_is_used_and_left_alone(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        """
        import os, sys
        sys.stderr.write(os.environ["HOME"] + "\\n" + os.getcwd() + "\\n")
        """,
    )
    work = tmp_path / "work"
    work.mkdir()
    (work / "paths.txt").write_text("a\n")
    run = await run_ffuf([], timeout_s=10, workdir=str(work))
    assert run.result.stderr.split() == [str(work), str(work)]
    assert (work / "paths.txt").exists()


# --- version -----------------------------------------------------------------------------


async def test_version_prefers_the_build_time_file(tmp_path, monkeypatch):
    vf = tmp_path / "ffuf.version"
    vf.write_text("v2.3.0\n")
    monkeypatch.setattr(ffuf_wrapper, "VERSION_FILE", vf)
    # even though `ffuf -V` would lie
    install_fake(tmp_path, monkeypatch, "print('ffuf version: 2.1.0-dev')\n")
    assert await ffuf_wrapper.version() == "v2.3.0"


async def test_version_falls_back_to_dash_V(tmp_path, monkeypatch):
    monkeypatch.setattr(ffuf_wrapper, "VERSION_FILE", tmp_path / "missing")
    install_fake(tmp_path, monkeypatch, "print('ffuf version: 2.1.0-dev')\n")
    assert await ffuf_wrapper.version() == "v2.1.0-dev"


async def test_version_ignores_an_empty_file_and_never_raises(tmp_path, monkeypatch):
    vf = tmp_path / "ffuf.version"
    vf.write_text("\n")
    monkeypatch.setattr(ffuf_wrapper, "VERSION_FILE", vf)
    install_fake(tmp_path, monkeypatch, "import sys\nsys.stderr.write('boom')\nsys.exit(3)\n")
    assert await ffuf_wrapper.version() is None
    monkeypatch.setattr(ffuf_wrapper, "VERSION_FILE", tmp_path)  # a directory: read raises OSError
    assert await ffuf_wrapper.version() is None


async def test_version_survives_a_hanging_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(ffuf_wrapper, "VERSION_FILE", tmp_path / "missing")
    install_fake(tmp_path, monkeypatch, "import time\ntime.sleep(60)\n")
    original = ffuf_wrapper.run_tool

    async def quick(binary, args, *, timeout_s=5.0, **kw):
        return await original(binary, args, timeout_s=0.5, **kw)

    monkeypatch.setattr(ffuf_wrapper, "run_tool", quick)
    assert await ffuf_wrapper.version() is None
