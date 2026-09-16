"""Pure-Python DNS resolution + wildcard detection. Always works — no
external binary required — which is what makes recon usable at all in an
environment without dnsx installed (docs/04 §B2 coverage-gap mitigation
extends to the tools themselves, not just the crawler).
"""

from __future__ import annotations

import secrets

import dns.asyncresolver
import dns.exception


async def resolve_a(host: str, *, timeout_s: float = 5.0) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout_s
    resolver.lifetime = timeout_s
    try:
        answer = await resolver.resolve(host, "A")
    except dns.exception.DNSException:
        return []
    return [str(rdata) for rdata in answer]


async def detect_wildcard_dns(root_domain: str) -> bool:
    """Probes a random, near-certainly-nonexistent subdomain. If it resolves
    anyway, the zone has wildcard DNS and every "discovered" subdomain under
    it needs to be treated with suspicion (docs/02 Phase 1 edge cases)."""
    probe_host = f"sentinel-wildcard-probe-{secrets.token_hex(8)}.{root_domain}"
    ips = await resolve_a(probe_host)
    return len(ips) > 0
