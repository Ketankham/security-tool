"""HTTP probing: prefer ProjectDiscovery's `httpx` binary (batch, fast) when
installed; otherwise probe with the Python `httpx` library directly. Either
path produces the same ``HttpProbeResult`` shape, so callers never need to
know which one ran (docs/04 §G — the honesty is in ``tool_availability``,
not in silently degraded output shape).
"""

from __future__ import annotations

import asyncio
import json
import re

import httpx as httpx_client

from .models import HttpProbeResult
from .tooling import looks_like_projectdiscovery_tool, run_tool

BINARY = "httpx"
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def is_available() -> bool:
    """Identity-verified, not just presence-on-PATH: the Python `httpx`
    *library* installs its own console script also named `httpx`, which
    would otherwise shadow ProjectDiscovery's Go binary — see
    tooling.looks_like_projectdiscovery_tool for why that distinction is
    load-bearing here, not pedantic."""
    return await looks_like_projectdiscovery_tool(BINARY)


async def probe_via_binary(hosts: list[str], *, timeout_s: float = 60.0) -> list[HttpProbeResult]:
    stdin = "\n".join(hosts)
    result = await run_tool(
        BINARY,
        ["-silent", "-json", "-title", "-server", "-tech-detect"],
        stdin=stdin,
        timeout_s=timeout_s,
    )
    if not result.ran or result.timed_out or result.returncode != 0:
        return []

    probes = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        probes.append(
            HttpProbeResult(
                url=doc.get("url", ""),
                status_code=doc.get("status_code"),
                title=doc.get("title"),
                server=doc.get("webserver"),
                tech=doc.get("tech", []) or [],
            )
        )
    return probes


async def _probe_one_via_python(
    client: httpx_client.AsyncClient, host: str
) -> HttpProbeResult | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp = await client.get(url)
        except httpx_client.HTTPError as exc:
            if scheme == "http":  # both schemes failed
                return HttpProbeResult(
                    url=url, status_code=None, title=None, server=None, error=str(exc)
                )
            continue
        title_match = _TITLE_RE.search(resp.content[:8192])
        title = title_match.group(1).decode(errors="replace").strip() if title_match else None
        return HttpProbeResult(
            url=str(resp.url),
            status_code=resp.status_code,
            title=title,
            server=resp.headers.get("server"),
        )
    return None


async def probe_via_python(
    hosts: list[str], *, timeout_s: float = 10.0, max_concurrency: int = 10
) -> list[HttpProbeResult]:
    """Fallback path used when the `httpx` binary isn't installed. Always
    available — this is what keeps the free unauthenticated scan meaningful
    even on a bare-bones deployment (docs/05 M3 lead-magnet requirement)."""
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded(client: httpx_client.AsyncClient, host: str) -> HttpProbeResult | None:
        async with semaphore:
            return await _probe_one_via_python(client, host)

    async with httpx_client.AsyncClient(
        timeout=timeout_s, follow_redirects=True, verify=True
    ) as client:
        results = await asyncio.gather(*(_bounded(client, h) for h in hosts))
    return [r for r in results if r is not None]


async def probe_hosts(
    hosts: list[str], *, timeout_s: float = 60.0, binary_available: bool | None = None
) -> list[HttpProbeResult]:
    """``binary_available`` lets a caller that already checked
    ``is_available()`` (e.g. the phase orchestrator, for its own
    ``tool_availability`` report) skip a second, redundant identity-check
    subprocess spawn."""
    if not hosts:
        return []
    if binary_available if binary_available is not None else await is_available():
        return await probe_via_binary(hosts, timeout_s=timeout_s)
    return await probe_via_python(hosts)
