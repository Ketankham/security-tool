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
import re
import shlex
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime


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


# What we keep of a tool's output in memory. Recon output is host names and
# probe JSON; anything past this is noise, and the store caps it again.
MAX_OUTPUT_BYTES = 2_000_000


async def _drain(stream: asyncio.StreamReader | None, sink: bytearray) -> None:
    if stream is None:
        return
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return
        if len(sink) < MAX_OUTPUT_BYTES:
            sink.extend(chunk[: MAX_OUTPUT_BYTES - len(sink)])


async def run_tool(
    binary_name: str, args: list[str], *, stdin: str | None = None, timeout_s: float = 30.0
) -> ToolRunResult:
    """Runs `binary_name args...`, returns ToolRunResult(ran=False) if the
    binary isn't on PATH rather than raising — callers always have a
    graceful-degrade path (docs/04 §B, §G).

    On a timeout the process is killed but what it printed so far is kept:
    subfinder streams results as it finds them, so a slow source should cost
    the remaining sources, not everything already found."""
    command = shlex.join([binary_name, *args])
    if not tool_available(binary_name):
        return ToolRunResult(ran=False, command=command)

    started = datetime.now(UTC)
    proc = await asyncio.create_subprocess_exec(
        binary_name,
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = bytearray(), bytearray()
    readers = asyncio.gather(_drain(proc.stdout, out), _drain(proc.stderr, err))
    if stdin is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin.encode())
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_s)
    except TimeoutError:
        timed_out = True
        proc.kill()
        await proc.wait()
    try:
        await asyncio.wait_for(readers, timeout=5)
    except TimeoutError:
        readers.cancel()
    return ToolRunResult(
        ran=True,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
        returncode=None if timed_out else proc.returncode,
        timed_out=timed_out,
        command=command,
        started_at=started,
        finished_at=datetime.now(UTC),
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
