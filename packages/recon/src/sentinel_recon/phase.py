"""Phase 1 orchestrator: Discovery & Recon (docs/02-scan-lifecycle.md Phase 1).

    result = await run_recon("acme.test")
    # result.assets, result.tool_availability, result.degraded, result.notes

Every step degrades independently and honestly: a missing `subfinder`
means fewer subdomains, not a crashed phase; a missing `httpx` binary means
the Python fallback runs instead. ``ReconResult.degraded`` and ``.notes``
are what the scan report surfaces to the customer (docs/04 §G).
"""

from __future__ import annotations

from . import http_probe, subfinder_wrapper, tlsx_wrapper
from .models import DiscoveredAsset, ReconResult
from .resolver import detect_wildcard_dns, resolve_a

MAX_CANDIDATE_HOSTS = (
    50  # cost/time ceiling for a single recon phase (docs/01 §3.4 budget discipline)
)


async def run_recon(root_domain: str) -> ReconResult:
    notes: list[str] = []
    tool_availability = {
        "subfinder": await subfinder_wrapper.is_available(),
        "httpx": await http_probe.is_available(),
        "tlsx": await tlsx_wrapper.is_available(),
    }

    wildcard = await detect_wildcard_dns(root_domain)
    if wildcard:
        notes.append(
            f"{root_domain} has wildcard DNS — any subdomain resolves, so subdomain "
            "discovery here is lower-confidence (docs/04 §F)."
        )

    candidate_hosts = {root_domain}
    if tool_availability["subfinder"]:
        found = await subfinder_wrapper.enumerate_subdomains(root_domain)
        candidate_hosts.update(found)
        notes.append(f"subfinder found {len(found)} candidate subdomain(s).")
    else:
        notes.append(
            "subfinder is not installed — subdomain discovery limited to the root domain "
            "itself (docs/adr/0002-build-vs-adopt-open-source.md)."
        )

    if len(candidate_hosts) > MAX_CANDIDATE_HOSTS:
        notes.append(
            f"{len(candidate_hosts)} candidate hosts found; capped to {MAX_CANDIDATE_HOSTS} "
            "for this scan (cost/time budget)."
        )
        candidate_hosts = set(sorted(candidate_hosts)[:MAX_CANDIDATE_HOSTS])

    resolved: dict[str, list[str]] = {}
    for host in candidate_hosts:
        ips = await resolve_a(host)
        if ips:
            resolved[host] = ips

    if not tool_availability["tlsx"]:
        notes.append(
            "tlsx is not installed — TLS/cipher grading (docs/03 §1) is skipped this scan."
        )

    probes = await http_probe.probe_hosts(
        sorted(resolved.keys()), binary_available=tool_availability["httpx"]
    )
    probes_by_host: dict[str, list] = {}
    for probe in probes:
        host = probe.url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        probes_by_host.setdefault(host, []).append(probe)

    assets = [
        DiscoveredAsset(
            host=host,
            source="root_domain" if host == root_domain else "subfinder",
            ips=ips,
            http_probes=probes_by_host.get(host, []),
        )
        for host, ips in sorted(resolved.items())
    ]

    return ReconResult(
        root_domain=root_domain,
        assets=assets,
        tool_availability=tool_availability,
        wildcard_dns_suspected=wildcard,
        notes=notes,
    )
