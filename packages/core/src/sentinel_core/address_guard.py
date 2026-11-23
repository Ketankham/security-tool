"""AddressGuard: refuses to send anything to a non-public address.

A client's DNS can say "staging.acme.com -> 10.0.0.5" (or 127.0.0.1, or the
cloud metadata address 169.254.169.254). The ScopeGuard checks host *names*
and cannot see that. Without this check a scan of acme.com would make our
worker open connections inside its own hosting network, which turns a
scanner into a way to probe that network.

Used by the HTTP engine (every request), the crawler (every navigation and
every browser sub-request) and recon (before probing a host). The check
resolves the name with the system resolver, as the browser and httpx do, and
looks at every address it returns (IPv4 and IPv6): one private address is
enough to refuse.

Not covered: a DNS answer that changes between this check and the request
(DNS rebinding). Closing that needs the connection itself pinned to the
checked address; noted as a known gap.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable

# host -> addresses it resolves to ([] if it doesn't resolve)
Resolver = Callable[[str], Awaitable[list[str]]]


def non_public_ips(ips: list[str]) -> list[str]:
    """The addresses among ``ips`` that are private, loopback, link-local
    (cloud metadata), CGNAT, reserved, multicast or unparseable."""
    bad = []
    for ip in ips:
        try:
            address = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            bad.append(ip)
            continue
        # is_global alone lets multicast through (224.0.0.0/4 counts as global).
        if not address.is_global or address.is_multicast:
            bad.append(ip)
    return bad


async def system_resolve(host: str) -> list[str]:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({str(info[4][0]) for info in infos})


class AddressGuard:
    def __init__(self, *, allow_private: bool = False, resolver: Resolver | None = None) -> None:
        self._allow_private = allow_private
        self._resolve = resolver or system_resolve
        self._cache: dict[str, str | None] = {}

    @property
    def allow_private(self) -> bool:
        return self._allow_private

    async def check(self, host: str) -> str | None:
        """None if requests to ``host`` may go ahead, else why not.

        A name that doesn't resolve is allowed: nothing can be reached
        through it, and the request will fail on its own."""
        if self._allow_private or not host:
            return None
        host = host.lower().strip("[]").rstrip(".")
        if host in self._cache:
            return self._cache[host]
        try:
            addresses = [str(ipaddress.ip_address(host.split("%", 1)[0]))]  # a literal IP
        except ValueError:
            addresses = await self._resolve(host)
        bad = non_public_ips(addresses)
        reason = (
            f"'{host}' resolves to a non-public address ({', '.join(bad)}); "
            "scans do not send requests to internal addresses."
            if bad
            else None
        )
        self._cache[host] = reason
        return reason
