from unittest.mock import AsyncMock, patch

import dns.exception
from sentinel_recon.resolver import detect_wildcard_dns, resolve_a


class _FakeRdata:
    def __init__(self, addr: str):
        self._addr = addr

    def __str__(self) -> str:
        return self._addr


async def test_resolve_a_returns_ips():
    with patch(
        "dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(return_value=[_FakeRdata("1.2.3.4"), _FakeRdata("1.2.3.5")]),
    ):
        ips = await resolve_a("example.test")
    assert ips == ["1.2.3.4", "1.2.3.5"]


async def test_resolve_a_returns_empty_on_nxdomain():
    with patch(
        "dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        ips = await resolve_a("nonexistent.test")
    assert ips == []


async def test_wildcard_detected_when_random_subdomain_resolves():
    with patch("sentinel_recon.resolver.resolve_a", new=AsyncMock(return_value=["1.2.3.4"])):
        assert await detect_wildcard_dns("acme.test") is True


async def test_wildcard_not_detected_when_random_subdomain_fails():
    with patch("sentinel_recon.resolver.resolve_a", new=AsyncMock(return_value=[])):
        assert await detect_wildcard_dns("acme.test") is False
