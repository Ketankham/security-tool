"""Generic external-binary runner (ADR-0002): shell out to MIT-licensed
ProjectDiscovery tools when present, and let every caller degrade cleanly
when they're not — this is the honesty mechanism from
docs/04-edge-cases.md §G, not an afterthought. A recon phase that silently
skips a missing tool and reports "clean" would be exactly the false-negative
failure mode docs/04 §B warns about; every wrapper here reports its own
availability into ``ReconResult.tool_availability`` instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shlex
import shutil
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

log = structlog.get_logger(__name__)


def tool_available(binary_name: str) -> bool:
    return shutil.which(binary_name) is not None


@dataclass(frozen=True, slots=True)
class ToolRunResult:
    ran: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    command: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    # Set when ``on_stdout_line`` returned False and the process was killed.
    stopped_reason: str | None = None
    # Set when ``cancel_check`` asked for the run to stop; ``cancelled_by`` is
    # whatever string the check returned (who cancelled).
    cancelled: bool = False
    cancelled_by: str | None = None


# What we keep of a tool's output in memory. Recon output is host names and
# probe JSON; anything past this is noise, and the store caps it again.
MAX_OUTPUT_BYTES = 2_000_000

# A stdout line longer than this is dropped from line callbacks (it is still
# kept in the captured output, up to MAX_OUTPUT_BYTES).
MAX_LINE_BYTES = 1_000_000

# How often cancel_check is asked.
CANCEL_POLL_INTERVAL_S = 1.0

STOPPED_BY_CALLER = "stopped early: the output filter asked for the run to end"


async def _drain(
    stream: asyncio.StreamReader | None,
    sink: bytearray,
    on_line: Callable[[str], None] | None = None,
) -> None:
    if stream is None:
        return
    pending = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if len(sink) < MAX_OUTPUT_BYTES:
            sink.extend(chunk[: MAX_OUTPUT_BYTES - len(sink)])
        if on_line is None:
            continue
        pending.extend(chunk)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                break
            line = bytes(pending[:newline])
            del pending[: newline + 1]
            on_line(line.decode(errors="replace").rstrip("\r"))
        if len(pending) > MAX_LINE_BYTES:
            pending.clear()  # one enormous line with no newline: not worth holding
    if on_line is not None and pending:
        on_line(bytes(pending).decode(errors="replace").rstrip("\r"))


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL the tool and everything it started. The tool runs in its own
    session (start_new_session), so its process group id is its pid; killing
    only the direct child would orphan helpers such as a tool's workers."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        proc.kill()


async def _poll_cancel(
    cancel_check: Callable[[], Awaitable[str | None]], on_cancel: Callable[[str], None]
) -> None:
    while True:
        await asyncio.sleep(CANCEL_POLL_INTERVAL_S)
        try:
            by = await cancel_check()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — a broken check must not kill the tool
            log.warning("tooling.cancel_check_failed", exc_info=True)
            continue
        if by is not None:
            on_cancel(by)
            return


async def run_tool(
    binary_name: str,
    args: list[str],
    *,
    stdin: str | None = None,
    timeout_s: float = 30.0,
    on_stdout_line: Callable[[str], bool] | None = None,
    cancel_check: Callable[[], Awaitable[str | None]] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> ToolRunResult:
    """Runs `binary_name args...`, returns ToolRunResult(ran=False) if the
    binary isn't on PATH rather than raising — callers always have a
    graceful-degrade path (docs/04 §B, §G).

    On a timeout the process is killed but what it printed so far is kept:
    subfinder streams results as it finds them, so a slow source should cost
    the remaining sources, not everything already found.

    The tool runs in its own process group and the whole group is killed on a
    timeout, a stop, a cancel, or when the awaiting task is cancelled or
    interrupted (CancelledError, Celery's SoftTimeLimitExceeded): nothing the
    tool started is left running.

    Optional, all off by default (existing callers are unaffected):
    - ``on_stdout_line``: called with each stdout line as it arrives. Returning
      False kills the tool and sets ``stopped_reason``; the output so far is kept.
      An exception in the callback also stops the tool (fail closed).
    - ``cancel_check``: awaited about once a second. Any non-None result (who
      cancelled) kills the tool and sets ``cancelled`` / ``cancelled_by``.
    - ``env``: merged over os.environ for this run only. ``cwd``: working directory.
    """
    command = shlex.join([binary_name, *args])
    if not tool_available(binary_name):
        return ToolRunResult(ran=False, command=command)

    started = datetime.now(UTC)
    full_env = {**os.environ, **env} if env is not None else None
    proc = await asyncio.create_subprocess_exec(
        binary_name,
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=full_env,
        cwd=cwd,
        start_new_session=True,
    )
    out, err = bytearray(), bytearray()
    stop_event = asyncio.Event()
    stopped_reason: str | None = None
    cancelled_by: str | None = None

    def handle_line(line: str) -> None:
        nonlocal stopped_reason
        if stopped_reason is not None or on_stdout_line is None:
            return
        try:
            keep_going = on_stdout_line(line)
        except Exception as exc:  # noqa: BLE001 — fail closed: stop the tool, say why
            stopped_reason = f"stopped early: the output filter failed ({type(exc).__name__})"
            stop_event.set()
            return
        if keep_going is False:
            stopped_reason = STOPPED_BY_CALLER
            stop_event.set()

    def handle_cancel(by: str) -> None:
        nonlocal cancelled_by
        cancelled_by = by
        stop_event.set()

    readers = asyncio.gather(
        _drain(proc.stdout, out, handle_line if on_stdout_line is not None else None),
        _drain(proc.stderr, err),
    )
    # Whoever ends up cancelling the readers, never leave their outcome unretrieved.
    readers.add_done_callback(lambda f: f.cancelled() or f.exception())
    waiter = asyncio.ensure_future(proc.wait())
    stopper = asyncio.ensure_future(stop_event.wait())
    canceller = (
        asyncio.ensure_future(_poll_cancel(cancel_check, handle_cancel)) if cancel_check else None
    )
    helpers = [t for t in (waiter, stopper, canceller) if t is not None]
    timed_out = False
    try:
        if stdin is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin.encode())
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()
        done, _ = await asyncio.wait(
            {waiter, stopper}, timeout=timeout_s, return_when=asyncio.FIRST_COMPLETED
        )
        if waiter not in done:
            if stopper in done:
                pass  # stopped by the callback or a cancel: reason already recorded
            else:
                timed_out = True
            _kill_process_group(proc)
            await proc.wait()
    except BaseException:
        # CancelledError, SoftTimeLimitExceeded, KeyboardInterrupt...: never
        # leave the tool (or its children) running behind a dead task.
        _kill_process_group(proc)
        with contextlib.suppress(BaseException):
            await asyncio.shield(proc.wait())
        readers.cancel()
        raise
    finally:
        for task in helpers:
            task.cancel()
        # Retrieve results so nothing logs "exception never retrieved".
        await asyncio.gather(*helpers, return_exceptions=True)
    try:
        await asyncio.wait_for(readers, timeout=5)
    except TimeoutError:
        readers.cancel()
    killed = timed_out or stopped_reason is not None or cancelled_by is not None
    return ToolRunResult(
        ran=True,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
        returncode=None if killed else proc.returncode,
        timed_out=timed_out,
        command=command,
        started_at=started,
        finished_at=datetime.now(UTC),
        stopped_reason=stopped_reason,
        cancelled=cancelled_by is not None,
        cancelled_by=cancelled_by,
    )


_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")


async def tool_version(binary_name: str, *, timeout_s: float = 5.0) -> str | None:
    """ProjectDiscovery tools print "Current Version: v2.17.0" (to stderr)."""
    result = await run_tool(binary_name, ["-version"], timeout_s=timeout_s)
    if not result.ran or result.timed_out:
        return None
    match = _VERSION_RE.search(result.stderr + result.stdout)
    return f"v{match.group(1)}" if match else None


async def looks_like_projectdiscovery_tool(
    binary_name: str, *, version_flag: str = "-version", timeout_s: float = 5.0
) -> bool:
    """A name on PATH is not proof of identity: this environment's own
    `.venv/bin/httpx` is the *Python* `httpx` library's CLI script, not
    ProjectDiscovery's Go binary of the same name — and without its optional
    `[cli]` extras installed, it exits non-zero on every invocation. Trusting
    `shutil.which` alone here would silently run the wrong tool, "succeed"
    with an empty result, and report the phase as non-degraded — precisely
    the false-negative failure mode docs/04-edge-cases.md §B warns about.

    ProjectDiscovery's tools are Go binaries that accept single-dash flags
    (including `-version`) and exit 0 on `-version`; that's what we check
    for, rather than pattern-matching banner text that could change.
    """
    if not tool_available(binary_name):
        return False
    result = await run_tool(binary_name, [version_flag], timeout_s=timeout_s)
    return result.ran and not result.timed_out and result.returncode == 0
