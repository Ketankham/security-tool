"""Phase 1 orchestrator: Discovery & Recon (docs/02-scan-lifecycle.md Phase 1).

    result = await run_recon("acme.test", host_check=..., requests_per_second=5)
    # result.assets, result.tool_runs, result.tool_availability, result.notes

Order of operations, and why:

1. subfinder (passive: asks public data sources, sends nothing to the target)
2. the candidate list is capped, always keeping the root domain and www
3. each host goes through the target's scope rules — an excluded host is
   neither resolved nor probed
4. DNS; a host resolving to a private/loopback/metadata address is not
   probed unless the worker explicitly allows it
5. HTTP probe of what's left, at the scan's speed setting

Every host found is returned, including the ones not probed, with the
reason — the tester asked to see what was skipped, not just what worked.
Every tool invocation is returned as a ToolRun (command, version, output).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from . import http_probe, subfinder_wrapper, tlsx_wrapper
from .models import (
    SCOPE_CAPPED,
    SCOPE_EXCLUDED,
    SCOPE_IN,
    SCOPE_PRIVATE_IP,
    SCOPE_UNRESOLVED,
    DiscoveredAsset,
    HttpProbeResult,
    ReconResult,
    ToolRun,
)
from .resolver import detect_wildcard_dns, non_public_ips, resolve_a
from .runs import skipped_run

MAX_CANDIDATE_HOSTS = 50  # hosts resolved + probed per scan on the light profile
FULL_MAX_CANDIDATE_HOSTS = 150  # ... and on the full profile
MAX_LISTED_HOSTS = 500  # hosts kept in the result at all (the rest only counted)
DNS_CONCURRENCY = 10

HostCheck = Callable[[str], str | None]  # host -> None if in scope, else why not
LogFn = Callable[[str, str], None]  # (level, message)


def _no_log(level: str, message: str) -> None:
    return None


def _prioritised(candidates: dict[str, list[str]], root: str) -> list[str]:
    first = [h for h in (root, f"www.{root}") if h in candidates]
    rest = sorted(h for h in candidates if h not in first)
    return first + rest


async def _resolve_all(hosts: list[str]) -> dict[str, list[str]]:
    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def one(host: str) -> tuple[str, list[str]]:
        async with semaphore:
            return host, await resolve_a(host)

    return dict(await asyncio.gather(*(one(h) for h in hosts)))


async def run_recon(
    root_domain: str,
    *,
    host_check: HostCheck | None = None,
    requests_per_second: float = 5.0,
    allow_private_ips: bool = False,
    profile: str = "light",
    log: LogFn | None = None,
) -> ReconResult:
    """``profile``: "light" (default) or "full": every subfinder data source
    and a higher host cap (see sentinel_core.scan_options)."""
    full = profile == "full"
    max_hosts = FULL_MAX_CANDIDATE_HOSTS if full else MAX_CANDIDATE_HOSTS
    log = log or _no_log
    root = root_domain.lower().rstrip(".")
    notes: list[str] = []
    tool_runs: list[ToolRun] = []
    tool_availability = {
        "subfinder": await subfinder_wrapper.is_available(),
        "httpx": await http_probe.is_available(),
        "tlsx": await tlsx_wrapper.is_available(),
    }

    wildcard = await detect_wildcard_dns(root)
    if wildcard:
        notes.append(
            f"{root} has wildcard DNS — any subdomain resolves, so subdomain "
            "discovery here is lower-confidence (docs/04 §F)."
        )

    # host -> where it came from
    candidates: dict[str, list[str]] = {root: ["root_domain"], f"www.{root}": ["common_name"]}
    if tool_availability["subfinder"]:
        args = subfinder_wrapper.build_args(root, all_sources=full)
        log("info", f"Running: {' '.join(['subfinder', *args])}")
        outcome = await subfinder_wrapper.run_subfinder(root, all_sources=full)
        tool_runs.append(outcome.run)
        for host, sources in outcome.hosts.items():
            merged = candidates.setdefault(host, [])
            merged.extend(s for s in (sources or ["subfinder"]) if s not in merged)
        run_status = outcome.run.status
        notes.append(
            f"subfinder ({run_status}) found {len(outcome.hosts)} subdomain(s) of {root}."
            if run_status == "ok"
            else f"subfinder {run_status.replace('_', ' ')} after finding {len(outcome.hosts)} "
            "subdomain(s); see its output in Tool runs."
        )
        if outcome.sources_without_key:
            notes.append(
                f"{len(outcome.sources_without_key)} subfinder data source(s) were skipped "
                f"because no API key is configured: {', '.join(outcome.sources_without_key)}."
            )
        if outcome.sources_failed:
            notes.append(
                f"subfinder data source(s) that returned an error: "
                f"{', '.join(outcome.sources_failed)}."
            )
    else:
        tool_runs.append(skipped_run("subfinder", "subfinder is not installed on the worker"))
        notes.append(
            "subfinder is not installed — subdomain discovery limited to the root domain "
            "and www (docs/adr/0002-build-vs-adopt-open-source.md)."
        )

    ordered = _prioritised(candidates, root)
    kept, over = ordered[:max_hosts], ordered[max_hosts:]
    if over:
        notes.append(
            f"{len(ordered)} candidate hosts found; only the first {max_hosts} "
            f"(root and www first, then A–Z) were checked this scan. Not checked: "
            f"{', '.join(over[:20])}{' …' if len(over) > 20 else ''}."
        )

    status: dict[str, tuple[str, str | None]] = {}
    for host in kept:
        reason = host_check(host) if host_check else None
        if reason:
            status[host] = (SCOPE_EXCLUDED, reason)
    excluded = [h for h in kept if h in status]
    if excluded:
        log("info", f"{len(excluded)} host(s) out of scope, not resolved or probed.")

    to_resolve = [h for h in kept if h not in status]
    started = datetime.now(UTC)
    resolved = await _resolve_all(to_resolve)
    dns_lines = [f"{h}\t{', '.join(ips) or 'no A record'}" for h, ips in resolved.items()]
    tool_runs.append(
        ToolRun(
            tool="dns (built-in)",
            status="ok",
            command=f"A-record lookup for {len(to_resolve)} host(s)",
            started_at=started,
            finished_at=datetime.now(UTC),
            exit_code=0,
            stdout="\n".join(dns_lines),
            results_count=sum(1 for ips in resolved.values() if ips),
        )
    )
    for host, ips in resolved.items():
        if not ips:
            status[host] = (SCOPE_UNRESOLVED, "No DNS A record.")
            continue
        bad = non_public_ips(ips)
        if bad and not allow_private_ips:
            status[host] = (
                SCOPE_PRIVATE_IP,
                f"Resolves to a non-public address ({', '.join(bad)}); not probed.",
            )
    private = [h for h, (s, _) in status.items() if s == SCOPE_PRIVATE_IP]
    if private:
        notes.append(
            f"{len(private)} host(s) resolve to private/internal addresses and were not "
            f"probed: {', '.join(private[:10])}."
        )

    to_probe = [h for h in to_resolve if h not in status]
    if not tool_availability["tlsx"]:
        notes.append(
            "tlsx is not installed — TLS/cipher grading (docs/03 §1) is skipped this scan."
        )
    if to_probe and tool_availability["httpx"]:
        log(
            "info",
            f"Running: {http_probe.BINARY} {' '.join(http_probe.build_args(requests_per_second))}"
            f"  (stdin: {len(to_probe)} host(s))",
        )
    probes, probe_runs = await http_probe.probe_hosts(
        to_probe,
        binary_available=tool_availability["httpx"],
        requests_per_second=requests_per_second,
    )
    tool_runs.extend(probe_runs)
    if not to_probe:
        tool_runs.append(skipped_run("httpx", "No in-scope host with a public address to probe."))
    probes_by_host: dict[str, list[HttpProbeResult]] = {}
    for probe in probes:
        host = probe.host or probe.url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        probes_by_host.setdefault(host.lower(), []).append(probe)

    assets = []
    for host in ordered[:MAX_LISTED_HOSTS]:
        scope_status, reason = status.get(host, (SCOPE_IN, None))
        if host in over:
            scope_status, reason = SCOPE_CAPPED, "Over the per-scan host limit."
        sources = candidates[host]
        ips = resolved.get(host, [])
        # www is only a guess; drop it when it doesn't exist.
        if sources == ["common_name"] and not ips:
            continue
        assets.append(
            DiscoveredAsset(
                host=host,
                source=sources[0] if sources[0] in ("root_domain", "common_name") else "subfinder",
                ips=ips,
                http_probes=probes_by_host.get(host, []),
                sources=sources,
                scope_status=scope_status,
                scope_reason=reason,
            )
        )
    if len(ordered) > MAX_LISTED_HOSTS:
        notes.append(f"{len(ordered) - MAX_LISTED_HOSTS} more host(s) were found but not listed.")

    return ReconResult(
        root_domain=root,
        assets=assets,
        tool_availability=tool_availability,
        wildcard_dns_suspected=wildcard,
        notes=notes,
        tool_runs=tool_runs,
    )
