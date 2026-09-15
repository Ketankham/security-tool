"""subfinder wrapper (MIT, ProjectDiscovery — see ADR-0002). Passive
subdomain enumeration only, per docs/02 Phase 1: `-passive` is implied by
never enabling brute-force flags, which would be noisy and scope-risky
against a customer's DNS infrastructure."""

from __future__ import annotations

import json

from .tooling import looks_like_projectdiscovery_tool, run_tool

BINARY = "subfinder"


async def is_available() -> bool:
    return await looks_like_projectdiscovery_tool(BINARY)


async def enumerate_subdomains(root_domain: str, *, timeout_s: float = 60.0) -> list[str]:
    """Returns [] (not an error) if subfinder isn't installed — callers
    check `is_available()` first if they need to distinguish "found nothing"
    from "couldn't look"."""
    result = await run_tool(BINARY, ["-d", root_domain, "-silent", "-json"], timeout_s=timeout_s)
    if not result.ran or result.timed_out or result.returncode != 0:
        return []

    hosts: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = doc.get("host")
        if host:
            hosts.add(host.lower())
    return sorted(hosts)
