"""AddressGuard: scans never send requests to non-public addresses."""

import pytest
from sentinel_core.address_guard import AddressGuard, non_public_ips


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",
        "224.0.0.1",  # multicast
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_flagged(ip):
    assert non_public_ips([ip]) == [ip]


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"])
def test_public_addresses_pass(ip):
    assert non_public_ips([ip]) == []


def fake_resolver(table, calls=None):
    async def resolve(host):
        if calls is not None:
            calls.append(host)
        return table.get(host, [])

    return resolve


async def test_public_hostname_resolving_to_private_address_is_refused():
    guard = AddressGuard(resolver=fake_resolver({"staging.acme.test": ["10.0.0.5"]}))
    reason = await guard.check("staging.acme.test")
    assert reason and "10.0.0.5" in reason and "non-public" in reason


async def test_one_private_answer_among_public_ones_is_enough_to_refuse():
    guard = AddressGuard(
        resolver=fake_resolver({"mixed.acme.test": ["93.184.216.34", "127.0.0.1"]})
    )
    assert await guard.check("mixed.acme.test") is not None


async def test_ipv6_loopback_answer_is_refused():
    guard = AddressGuard(resolver=fake_resolver({"v6.acme.test": ["::1"]}))
    assert await guard.check("v6.acme.test") is not None


async def test_public_hostname_is_allowed():
    guard = AddressGuard(resolver=fake_resolver({"www.acme.test": ["93.184.216.34"]}))
    assert await guard.check("www.acme.test") is None


async def test_literal_ip_hosts_are_checked_without_dns():
    calls: list[str] = []
    guard = AddressGuard(resolver=fake_resolver({}, calls))
    assert await guard.check("127.0.0.1") is not None
    assert await guard.check("[::1]") is not None
    assert await guard.check("169.254.169.254") is not None
    assert await guard.check("93.184.216.34") is None
    assert calls == []


async def test_unresolvable_name_is_allowed_because_nothing_can_be_reached():
    guard = AddressGuard(resolver=fake_resolver({}))
    assert await guard.check("gone.acme.test") is None


async def test_case_and_trailing_dot_are_normalised_and_answers_cached():
    calls: list[str] = []
    guard = AddressGuard(resolver=fake_resolver({"a.acme.test": ["10.1.1.1"]}, calls))
    assert await guard.check("A.Acme.Test.") is not None
    assert await guard.check("a.acme.test") is not None
    assert calls == ["a.acme.test"]


async def test_allow_private_switches_the_guard_off_for_local_testing():
    guard = AddressGuard(allow_private=True, resolver=fake_resolver({"x.test": ["127.0.0.1"]}))
    assert await guard.check("x.test") is None
    assert await guard.check("127.0.0.1") is None
