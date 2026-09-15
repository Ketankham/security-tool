"""Unit tests for the ownership verification service (no live DB needed —
these mock DNS resolution and HTTP directly)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.exception
import httpx
from sentinel_api_app.services.ownership import (
    generate_verification_token,
    verify_dns_txt,
    verify_meta_tag,
    verify_well_known_file,
)


def test_generate_verification_token_is_unique_and_prefixed():
    tokens = {generate_verification_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(t.startswith("sentinel-verify=") for t in tokens)


class _FakeRdata:
    def __init__(self, value: bytes):
        self.strings = [value]


async def test_dns_txt_matches():
    token = "sentinel-verify=abc123"
    with patch(
        "dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(return_value=[_FakeRdata(token.encode())]),
    ):
        result = await verify_dns_txt("acme.test", token)
    assert result.verified


async def test_dns_txt_no_match():
    with patch(
        "dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(return_value=[_FakeRdata(b"sentinel-verify=other")]),
    ):
        result = await verify_dns_txt("acme.test", "sentinel-verify=abc123")
    assert not result.verified


async def test_dns_txt_lookup_failure_is_not_verified():
    with patch(
        "dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        result = await verify_dns_txt("nonexistent.test", "sentinel-verify=abc123")
    assert not result.verified
    assert "failed" in result.detail.lower()


async def test_well_known_file_matches(respx_mock=None):
    import respx

    token = "sentinel-verify=xyz"
    with respx.mock:
        respx.get("https://acme.test/.well-known/sentinel-verify.txt").mock(
            return_value=httpx.Response(200, text=token)
        )
        result = await verify_well_known_file("acme.test", token)
    assert result.verified


async def test_well_known_file_wrong_content():
    import respx

    with respx.mock:
        respx.get("https://acme.test/.well-known/sentinel-verify.txt").mock(
            return_value=httpx.Response(200, text="wrong-token")
        )
        result = await verify_well_known_file("acme.test", "sentinel-verify=xyz")
    assert not result.verified


async def test_meta_tag_matches():
    import respx

    token = "sentinel-verify=meta123"
    html = f'<html><head><meta name="sentinel-verify" content="{token}"></head></html>'
    with respx.mock:
        respx.get("https://acme.test/").mock(return_value=httpx.Response(200, text=html))
        result = await verify_meta_tag("acme.test", token)
    assert result.verified


async def test_meta_tag_missing():
    import respx

    with respx.mock:
        respx.get("https://acme.test/").mock(return_value=httpx.Response(200, text="<html></html>"))
        result = await verify_meta_tag("acme.test", "sentinel-verify=meta123")
    assert not result.verified
