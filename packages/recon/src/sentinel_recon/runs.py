"""Turns a raw subprocess result into the ToolRun record a tester reads."""

from __future__ import annotations

from .models import ToolRun
from .tooling import ToolRunResult


def tool_run_from(
    tool: str,
    result: ToolRunResult,
    *,
    binary: str | None,
    version: str | None,
    results_count: int,
) -> ToolRun:
    if not result.ran:
        status = "not_installed"
    elif result.timed_out:
        status = "timed_out"
    elif result.returncode != 0:
        status = "failed"
    else:
        status = "ok"
    return ToolRun(
        tool=tool,
        status=status,
        command=result.command,
        binary=binary,
        version=version,
        started_at=result.started_at,
        finished_at=result.finished_at,
        exit_code=result.returncode,
        timed_out=result.timed_out,
        stdout=result.stdout,
        stderr=result.stderr,
        results_count=results_count,
        skip_reason=f"{binary or tool} is not installed on the worker" if not result.ran else None,
    )


def skipped_run(tool: str, reason: str, *, command: str = "") -> ToolRun:
    return ToolRun(tool=tool, status="skipped", command=command, skip_reason=reason)
