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
import shutil
from dataclasses import dataclass


def tool_available(binary_name: str) -> bool:
    return shutil.which(binary_name) is not None


@dataclass(frozen=True, slots=True)
class ToolRunResult:
    ran: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False


async def run_tool(
    binary_name: str, args: list[str], *, stdin: str | None = None, timeout_s: float = 30.0
) -> ToolRunResult:
    """Runs `binary_name args...`, returns ToolRunResult(ran=False) if the
    binary isn't on PATH rather than raising — callers always have a
    graceful-degrade path (docs/04 §B, §G)."""
    if not tool_available(binary_name):
        return ToolRunResult(ran=False)

    proc = await asyncio.create_subprocess_exec(
        binary_name,
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout=timeout_s
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return ToolRunResult(ran=True, timed_out=True)

    return ToolRunResult(
        ran=True,
        stdout=stdout_b.decode(errors="replace"),
        stderr=stderr_b.decode(errors="replace"),
        returncode=proc.returncode,
    )


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
