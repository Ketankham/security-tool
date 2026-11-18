"""HTTP probing: prefer ProjectDiscovery's `httpx` binary (batch, fast, with
Wappalyzer-based technology detection) when installed; otherwise probe with
the Python `httpx` library directly. Either path produces the same
``HttpProbeResult`` shape plus a ``ToolRun`` record of what ran.

Both paths respect the scan's speed setting: the binary gets ``-rl`` (and a
small thread count), the fallback spaces out its request starts.

Callers pass only hosts that already passed the scope and public-address
checks: httpx's own ``-deny`` filter does not cover host names that resolve
to a denied address (checked against v1.6.10), so it cannot be the guard.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import UTC, datetime

import httpx as httpx_client

from .models import HttpProbeResult, ToolRun
from .runs import tool_run_from
from .tooling import looks_like_projectdiscovery_tool, run_tool, tool_version

# The worker image installs ProjectDiscovery's httpx as `pd-httpx`: the
# venv's Python `httpx` console script owns the plain name on PATH.
BINARY_CANDIDATES = ("pd-httpx", "httpx")
BINARY = BINARY_CANDIDATES[0]
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
BUILTIN_TOOL = "http-probe (built-in)"


async def is_available() -> bool:
    """Identity-verified, not just presence-on-PATH: the Python `httpx`
    *library* installs its own console script also named `httpx`, which
    would otherwise shadow ProjectDiscovery's Go binary — see
    tooling.looks_like_projectdiscovery_tool for why that distinction is
    load-bearing here, not pedantic."""
    return await _binary() is not None


async def _binary() -> str | None:
    for name in BINARY_CANDIDATES:
        if await looks_like_projectdiscovery_tool(name):
            return name
    return None


def build_args(requests_per_second: float) -> list[str]:
    rps = max(1, int(requests_per_second))
    return [
        "-json", "-probe",  # -probe: failed hosts get a line too, with the error
        "-sc", "-title", "-server", "-td", "-ip", "-cdn", "-ct",
        "-rl", str(rps), "-t", str(min(rps, 10)),
        "-timeout", "10", "-retries", "1",
        "-nc", "-duc",
    ]  # fmt: skip


def _host_of(value: str) -> str:
    return value.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()


def parse_binary_output(stdout: str) -> list[HttpProbeResult]:
    probes = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue
        failed = bool(doc.get("failed"))
        status = doc.get("status_code")
        probes.append(
            HttpProbeResult(
                url=doc.get("url", ""),
                status_code=None if failed or not status else int(status),
                title=doc.get("title"),
                server=doc.get("webserver"),
                tech=[str(t) for t in (doc.get("tech") or [])],
                error=doc.get("error") if failed else None,
                host=_host_of(str(doc.get("input") or doc.get("url") or "")),
                cdn=doc.get("cdn_name") or None,
                content_type=doc.get("content_type"),
            )
        )
    return probes


async def probe_via_binary(
    hosts: list[str], *, timeout_s: float = 300.0, requests_per_second: float = 5.0
) -> tuple[list[HttpProbeResult], ToolRun]:
    binary = await _binary() or BINARY
    version = await tool_version(binary)
    result = await run_tool(
        binary, build_args(requests_per_second), stdin="\n".join(hosts), timeout_s=timeout_s
    )
    probes = parse_binary_output(result.stdout) if result.ran else []
    run = tool_run_from(
        "httpx",
        result,
        binary=binary,
        version=version,
        results_count=sum(1 for p in probes if p.status_code is not None),
    )
    return probes, run


async def _probe_one_via_python(
    client: httpx_client.AsyncClient, host: str, throttle: _Throttle | None = None
) -> HttpProbeResult | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        if throttle is not None:
            await throttle.wait()
        try:
            resp = await client.get(url)
        except httpx_client.HTTPError as exc:
            if scheme == "http":  # both schemes failed
                return HttpProbeResult(
                    url=url,
                    status_code=None,
                    title=None,
                    server=None,
                    error=str(exc) or type(exc).__name__,
                    host=host,
                )
            continue
        title_match = _TITLE_RE.search(resp.content[:8192])
        title = title_match.group(1).decode(errors="replace").strip() if title_match else None
        return HttpProbeResult(
            url=str(resp.url),
            status_code=resp.status_code,
            title=title,
            server=resp.headers.get("server"),
            host=host,
            content_type=(resp.headers.get("content-type") or "").split(";")[0] or None,
        )
    return None


class _Throttle:
    """Spaces request starts at most ``rate`` per second."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            await asyncio.sleep(delay)


async def probe_via_python(
    hosts: list[str],
    *,
    timeout_s: float = 10.0,
    max_concurrency: int = 10,
    requests_per_second: float | None = None,
) -> list[HttpProbeResult]:
    """Fallback path used when the `httpx` binary isn't installed. Always
    available — this is what keeps the free unauthenticated scan meaningful
    even on a bare-bones deployment (docs/05 M3 lead-magnet requirement)."""
    semaphore = asyncio.Semaphore(max_concurrency)
    throttle = _Throttle(requests_per_second) if requests_per_second else None

    async def _bounded(client: httpx_client.AsyncClient, host: str) -> HttpProbeResult | None:
        async with semaphore:
            return await _probe_one_via_python(client, host, throttle)

    async with httpx_client.AsyncClient(
        # No redirect following: a redirect can point off-scope, and the
        # binary path (no -fr) reports the 30x itself too.
        timeout=timeout_s,
        follow_redirects=False,
        verify=True,
    ) as client:
        results = await asyncio.gather(*(_bounded(client, h) for h in hosts))
    return [r for r in results if r is not None]


def _python_run(hosts: list[str], probes: list[HttpProbeResult], started: datetime) -> ToolRun:
    lines = [
        json.dumps(
            {
                "input": p.host,
                "url": p.url,
                "status_code": p.status_code,
                "title": p.title,
                "webserver": p.server,
                "content_type": p.content_type,
                "error": p.error,
            }
        )
        for p in probes
    ]
    return ToolRun(
        tool=BUILTIN_TOOL,
        status="ok",
        command=f"GET https:// then http:// for {len(hosts)} host(s) (built-in, no httpx binary)",
        started_at=started,
        finished_at=datetime.now(UTC),
        exit_code=0,
        stdout="\n".join(lines),
        results_count=sum(1 for p in probes if p.status_code is not None),
    )


async def probe_hosts(
    hosts: list[str],
    *,
    timeout_s: float = 300.0,
    binary_available: bool | None = None,
    requests_per_second: float = 5.0,
) -> tuple[list[HttpProbeResult], list[ToolRun]]:
    """``binary_available`` lets a caller that already checked
    ``is_available()`` (e.g. the phase orchestrator, for its own
    ``tool_availability`` report) skip a second identity-check spawn."""
    if not hosts:
        return [], []
    if binary_available if binary_available is not None else await is_available():
        probes, run = await probe_via_binary(
            hosts, timeout_s=timeout_s, requests_per_second=requests_per_second
        )
        if run.status == "ok":
            return probes, [run]
        # The binary misbehaved (crash, timeout): fall through to the
        # built-in prober so the scan still learns which hosts are live,
        # and keep the failed run in the record.
        started = datetime.now(UTC)
        fallback = await probe_via_python(hosts, requests_per_second=requests_per_second)
        seen = {p.host for p in probes if p.status_code is not None}
        merged = [p for p in probes if p.status_code is not None] + [
            p for p in fallback if p.host not in seen
        ]
        return merged, [run, _python_run(hosts, fallback, started)]
    started = datetime.now(UTC)
    probes = await probe_via_python(hosts, requests_per_second=requests_per_second)
    return probes, [_python_run(hosts, probes, started)]
