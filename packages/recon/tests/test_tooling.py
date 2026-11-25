import pytest
from sentinel_recon.tooling import run_tool, tool_available


def test_tool_available_true_for_a_real_binary():
    assert tool_available("sh") is True


def test_tool_available_false_for_nonexistent_binary():
    assert tool_available("definitely-not-a-real-binary-xyz") is False


async def test_run_tool_returns_not_ran_when_binary_missing():
    result = await run_tool("definitely-not-a-real-binary-xyz", ["-v"])
    assert result.ran is False


async def test_run_tool_captures_stdout_of_a_real_command():
    result = await run_tool("echo", ["hello"])
    assert result.ran is True
    assert result.stdout.strip() == "hello"
    assert result.returncode == 0


async def test_run_tool_times_out():
    result = await run_tool("sleep", ["5"], timeout_s=0.1)
    assert result.ran is True
    assert result.timed_out is True


async def test_looks_like_projectdiscovery_tool_false_when_missing():
    from sentinel_recon.tooling import looks_like_projectdiscovery_tool

    assert await looks_like_projectdiscovery_tool("definitely-not-a-real-binary-xyz") is False


async def test_looks_like_projectdiscovery_tool_true_when_version_flag_exits_zero():
    from unittest.mock import AsyncMock, patch

    from sentinel_recon.tooling import ToolRunResult, looks_like_projectdiscovery_tool

    with (
        patch("sentinel_recon.tooling.tool_available", return_value=True),
        patch(
            "sentinel_recon.tooling.run_tool",
            new=AsyncMock(return_value=ToolRunResult(ran=True, returncode=0, stdout="v1.2.3")),
        ),
    ):
        assert await looks_like_projectdiscovery_tool("httpx") is True


async def test_looks_like_projectdiscovery_tool_false_for_shadowing_binary():
    """Regression test for a real bug found in this sandbox: the *Python*
    httpx library installs its own `httpx` console script on PATH, which
    (without its optional [cli] extras) exits non-zero on every invocation.
    Naive `shutil.which`-only availability checks would silently treat it
    as ProjectDiscovery's httpx and get zero real probe results back —
    exactly the false-negative failure mode docs/04-edge-cases.md §B and §G
    exist to prevent."""
    from unittest.mock import AsyncMock, patch

    from sentinel_recon.tooling import ToolRunResult, looks_like_projectdiscovery_tool

    with (
        patch("sentinel_recon.tooling.tool_available", return_value=True),
        patch(
            "sentinel_recon.tooling.run_tool",
            new=AsyncMock(
                return_value=ToolRunResult(
                    ran=True,
                    returncode=1,
                    stderr="The httpx command line client could not run because the "
                    "required dependencies were not installed.",
                )
            ),
        ),
    ):
        assert await looks_like_projectdiscovery_tool("httpx") is False


async def test_http_probe_prefers_the_pd_httpx_name():
    """The worker image installs ProjectDiscovery's httpx as `pd-httpx`
    (the plain `httpx` on PATH is the Python library's script)."""
    from unittest.mock import AsyncMock, patch

    from sentinel_recon import http_probe

    async def only_pd(name, **_):
        return name == "pd-httpx"

    with patch.object(
        http_probe, "looks_like_projectdiscovery_tool", AsyncMock(side_effect=only_pd)
    ):
        assert await http_probe.is_available() is True
        assert await http_probe._binary() == "pd-httpx"

    with patch.object(
        http_probe, "looks_like_projectdiscovery_tool", AsyncMock(return_value=False)
    ):
        assert await http_probe.is_available() is False


async def test_run_tool_keeps_output_printed_before_a_timeout():
    result = await run_tool("sh", ["-c", "echo partial; sleep 5"], timeout_s=0.5)
    assert result.timed_out is True
    assert result.returncode is None
    assert "partial" in result.stdout
    assert result.started_at is not None and result.finished_at is not None


async def test_run_tool_records_command_and_passes_stdin():
    result = await run_tool("cat", [], stdin="a.test\nb.test")
    assert result.stdout == "a.test\nb.test"
    assert result.command == "cat"


# --- Subprocess hardening: process groups, stop callback, cancel check ---------

import asyncio  # noqa: E402
import os  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from sentinel_recon.runs import tool_run_from  # noqa: E402
from sentinel_recon.tooling import ToolRunResult  # noqa: E402


def _alive(pid: int) -> bool:
    """True while the process exists and is not a zombie (a killed orphan can
    linger as a zombie until its adopter reaps it; that is not running)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


async def _wait_gone(pid: int, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        await asyncio.sleep(0.05)
    return not _alive(pid)


async def test_new_arguments_default_to_the_old_behaviour():
    result = await run_tool("echo", ["same as before"])
    assert result.stdout.strip() == "same as before"
    assert result.stopped_reason is None
    assert result.cancelled is False
    assert result.cancelled_by is None
    assert result.timed_out is False


async def test_tool_runs_in_its_own_process_group():
    result = await run_tool("sh", ["-c", 'echo "$$ $(cut -d" " -f5 /proc/$$/stat)"'])
    pid, pgrp = result.stdout.split()
    assert pid == pgrp  # a session/group leader: killing the group cannot touch us
    assert int(pgrp) != os.getpgrp()


async def test_timeout_kills_the_whole_process_group():
    result = await run_tool("sh", ["-c", "sleep 30 & echo $!; sleep 30"], timeout_s=0.5)
    assert result.timed_out is True
    child = int(result.stdout.split()[0])
    assert await _wait_gone(child), "the background child outlived the timeout"


async def test_env_is_merged_over_the_environment_and_cwd_is_applied(tmp_path):
    result = await run_tool(
        "sh",
        ["-c", 'echo "$SENTINEL_TEST_VAR|$HOME|$(pwd)"'],
        env={"SENTINEL_TEST_VAR": "hello", "HOME": str(tmp_path)},
        cwd=str(tmp_path),
    )
    value, home, cwd = result.stdout.strip().split("|")
    assert value == "hello"
    assert home == str(tmp_path)
    assert Path(cwd).resolve() == tmp_path.resolve()
    assert "SENTINEL_TEST_VAR" not in os.environ  # per-run only


async def test_env_default_inherits_the_environment(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_INHERITED", "yes")
    result = await run_tool("sh", ["-c", "echo $SENTINEL_TEST_INHERITED"])
    assert result.stdout.strip() == "yes"


async def test_stdout_lines_are_delivered_in_order_including_an_unterminated_last_line():
    seen: list[str] = []

    def on_line(line: str) -> bool:
        seen.append(line)
        return True

    result = await run_tool("sh", ["-c", "printf 'one\\ntwo\\r\\nthree'"], on_stdout_line=on_line)
    assert seen == ["one", "two", "three"]
    assert result.stopped_reason is None
    assert result.returncode == 0


async def test_stop_callback_kills_the_tool_and_keeps_what_it_printed():
    seen: list[str] = []

    def on_line(line: str) -> bool:
        seen.append(line)
        return line != "stop-here"

    started = time.monotonic()
    result = await run_tool(
        "sh",
        ["-c", "echo first; echo stop-here; sleep 30"],
        on_stdout_line=on_line,
        timeout_s=20,
    )
    assert time.monotonic() - started < 10
    assert result.stopped_reason
    assert result.timed_out is False
    assert result.cancelled is False
    assert result.returncode is None
    assert "first" in result.stdout and "stop-here" in result.stdout
    assert seen == ["first", "stop-here"]  # nothing is delivered after the stop


async def test_stop_callback_kills_background_children_too(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = f"sleep 30 & echo $! > {pidfile}; echo go; sleep 30"
    result = await run_tool("sh", ["-c", script], on_stdout_line=lambda _l: False, timeout_s=20)
    assert result.stopped_reason
    # the pid file is written before 'go' is printed
    child = int(pidfile.read_text())
    assert await _wait_gone(child)


async def test_a_failing_stop_callback_stops_the_tool_instead_of_being_ignored():
    def broken(_line: str) -> bool:
        raise ValueError("boom")

    result = await run_tool("sh", ["-c", "echo x; sleep 30"], on_stdout_line=broken, timeout_s=20)
    assert result.stopped_reason and "failed" in result.stopped_reason
    assert result.returncode is None


async def test_cancel_check_kills_the_tool_and_reports_who():
    calls = 0

    async def cancel_check() -> str | None:
        nonlocal calls
        calls += 1
        return "bob" if calls >= 2 else None

    started = time.monotonic()
    result = await run_tool("sleep", ["30"], cancel_check=cancel_check, timeout_s=60)
    elapsed = time.monotonic() - started
    assert result.cancelled is True
    assert result.cancelled_by == "bob"
    assert result.timed_out is False
    assert result.stopped_reason is None
    assert result.returncode is None
    assert 1.5 < elapsed < 6  # polled about once a second


async def test_cancel_check_kills_background_children_too(tmp_path):
    pidfile = tmp_path / "child.pid"

    async def cancel_check() -> str | None:
        return "carol" if pidfile.exists() else None

    result = await run_tool(
        "sh",
        ["-c", f"sleep 30 & echo $! > {pidfile}; sleep 30"],
        cancel_check=cancel_check,
        timeout_s=30,
    )
    assert result.cancelled_by == "carol"
    assert await _wait_gone(int(pidfile.read_text()))


async def test_cancel_check_that_says_none_lets_the_tool_finish():
    async def never() -> str | None:
        return None

    result = await run_tool("sh", ["-c", "sleep 1.2; echo done"], cancel_check=never)
    assert result.cancelled is False
    assert result.stdout.strip() == "done"
    assert result.returncode == 0


async def test_a_cancel_check_that_raises_does_not_kill_the_tool():
    async def broken() -> str | None:
        raise ConnectionError("redis is down")

    result = await run_tool("sh", ["-c", "sleep 1.2; echo done"], cancel_check=broken)
    assert result.cancelled is False
    assert result.stdout.strip() == "done"


async def test_cancelling_the_awaiting_task_kills_the_tool_and_its_children(tmp_path):
    pidfile = tmp_path / "child.pid"
    task = asyncio.ensure_future(
        run_tool("sh", ["-c", f"sleep 30 & echo $! > {pidfile}; sleep 30"], timeout_s=60)
    )
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        await asyncio.sleep(0.05)
    child = int(pidfile.read_text())
    assert _alive(child)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await _wait_gone(child), "CancelledError left the tool's child running"


async def test_an_unexpected_exception_while_waiting_also_kills_the_tool(tmp_path, monkeypatch):
    """Celery's SoftTimeLimitExceeded surfaces as an exception inside the
    running coroutine; whatever its type, nothing may be left behind."""
    pidfile = tmp_path / "child.pid"

    class SoftLimit(Exception):  # noqa: N818
        pass

    real_wait = asyncio.wait

    async def exploding_wait(*args, **kwargs):
        for _ in range(100):  # let the tool start and write its pid
            if pidfile.exists() and pidfile.read_text().strip():
                break
            await asyncio.sleep(0.05)
        raise SoftLimit

    monkeypatch.setattr("sentinel_recon.tooling.asyncio.wait", exploding_wait)
    with pytest.raises(SoftLimit):
        await run_tool("sh", ["-c", f"sleep 30 & echo $! > {pidfile}; sleep 30"], timeout_s=60)
    monkeypatch.setattr("sentinel_recon.tooling.asyncio.wait", real_wait)
    assert await _wait_gone(int(pidfile.read_text()))


async def test_many_output_lines_do_not_stall_the_callback_after_the_capture_cap():
    count = 0

    def on_line(_line: str) -> bool:
        nonlocal count
        count += 1
        return True

    # ~3 MB of output: stored truncated, but every line still reaches the callback.
    result = await run_tool(
        "sh",
        ["-c", f"yes {'x' * 99} | head -n 30000"],
        on_stdout_line=on_line,
        timeout_s=60,
    )
    assert count == 30000
    assert result.returncode == 0


def test_tool_run_from_maps_every_outcome_to_a_status():
    def run(**kwargs):
        return tool_run_from(
            "ffuf",
            ToolRunResult(ran=kwargs.pop("ran", True), command="ffuf", **kwargs),
            binary="ffuf",
            version="2.3.0",
            results_count=0,
        )

    assert run(returncode=0).status == "ok"
    assert run(returncode=2).status == "failed"
    assert run(ran=False).status == "not_installed"
    assert run(ran=False).skip_reason == "ffuf is not installed on the worker"
    assert run(timed_out=True).status == "timed_out"
    stopped = run(stopped_reason="rate limited (429)")
    assert stopped.status == "stopped"
    assert stopped.skip_reason == "rate limited (429)"
    cancelled = run(cancelled=True, cancelled_by="bob")
    assert cancelled.status == "cancelled"
    assert cancelled.skip_reason == "Cancelled by bob"
    assert run(cancelled=True).skip_reason == "Cancelled by unknown"
    assert run(returncode=0).skip_reason is None
