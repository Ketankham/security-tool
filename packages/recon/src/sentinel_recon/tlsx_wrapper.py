"""tlsx wrapper (MIT, ProjectDiscovery — see ADR-0002). TLS/cipher grading
is genuinely hard to do well in pure Python without adding a large
dependency, so this one has no fallback: when the binary isn't present we
skip it and say so honestly (docs/04 §G) rather than fake a result.
"""

from __future__ import annotations

import json

from .tooling import looks_like_projectdiscovery_tool, run_tool

BINARY = "tlsx"


async def is_available() -> bool:
    return await looks_like_projectdiscovery_tool(BINARY)


async def probe_tls(hosts: list[str], *, timeout_s: float = 60.0) -> list[dict]:
    if not hosts:
        return []
    result = await run_tool(
        BINARY, ["-silent", "-json"], stdin="\n".join(hosts), timeout_s=timeout_s
    )
    if not result.ran or result.timed_out or result.returncode != 0:
        return []

    records = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
