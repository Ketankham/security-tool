"""Ownership verification (docs/06-safety-legal-abuse.md §1).

The hard legal gate: no authenticated or active scan runs against a target
until we've confirmed the customer actually controls it. Three methods,
matching docs/02 Phase 0 step 2 — DNS TXT, a well-known file, or a meta tag.
All three are genuinely implemented (not stubbed) because this is the one
piece of the platform that must never be faked, even in a v1 skeleton.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import httpx
from sentinel_db.enums import OwnershipVerificationMethod

TOKEN_PREFIX = "sentinel-verify"


def generate_verification_token() -> str:
    return f"{TOKEN_PREFIX}={secrets.token_hex(16)}"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verified: bool
    detail: str


async def verify_dns_txt(
    domain: str, expected_token: str, *, timeout_s: float = 5.0
) -> VerificationResult:
    record_name = f"_sentinel-verify.{domain}"
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = timeout_s
        resolver.lifetime = timeout_s
        answer = await resolver.resolve(record_name, "TXT")
    except dns.exception.DNSException as exc:
        return VerificationResult(False, f"DNS TXT lookup for {record_name} failed: {exc}")

    for rdata in answer:
        # dnspython TXT records are sequences of byte-strings; join them.
        value = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if value.strip() == expected_token:
            return VerificationResult(True, f"Matched TXT record at {record_name}.")

    return VerificationResult(False, f"No TXT record at {record_name} matched the expected token.")


async def verify_well_known_file(
    domain: str, expected_token: str, *, timeout_s: float = 10.0
) -> VerificationResult:
    url = f"https://{domain}/.well-known/sentinel-verify.txt"
    try:
        async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        return VerificationResult(False, f"Fetching {url} failed: {exc}")

    if resp.status_code != 200:
        return VerificationResult(False, f"{url} returned HTTP {resp.status_code}.")
    if resp.text.strip() == expected_token:
        return VerificationResult(True, f"Matched file content at {url}.")
    return VerificationResult(False, f"Content at {url} did not match the expected token.")


_META_TAG_RE = re.compile(
    r"""<meta\s+[^>]*name=["']sentinel-verify["'][^>]*content=["']([^"']+)["']""", re.IGNORECASE
)


async def verify_meta_tag(
    domain: str, expected_token: str, *, timeout_s: float = 10.0
) -> VerificationResult:
    url = f"https://{domain}/"
    try:
        async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        return VerificationResult(False, f"Fetching {url} failed: {exc}")

    if resp.status_code != 200:
        return VerificationResult(False, f"{url} returned HTTP {resp.status_code}.")

    match = _META_TAG_RE.search(resp.text)
    if match and match.group(1).strip() == expected_token:
        return VerificationResult(True, f'Matched <meta name="sentinel-verify"> tag at {url}.')
    return VerificationResult(False, f"No matching sentinel-verify meta tag found at {url}.")


async def verify_ownership(
    method: OwnershipVerificationMethod, domain: str, expected_token: str
) -> VerificationResult:
    if method is OwnershipVerificationMethod.DNS_TXT:
        return await verify_dns_txt(domain, expected_token)
    if method is OwnershipVerificationMethod.WELL_KNOWN_FILE:
        return await verify_well_known_file(domain, expected_token)
    if method is OwnershipVerificationMethod.META_TAG:
        return await verify_meta_tag(domain, expected_token)
    raise ValueError(f"Unknown verification method: {method}")
