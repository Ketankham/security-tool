"""Normalising what users type into "Root domain" (QA bug log 2026-11-12
#1/#12). The value feeds DNS-record names, verification URLs and the scope
guard's allowed hosts, so `https://www.example.com/path` must not be stored
verbatim (it produced `_sentinel-verify.https://…` and `https://https://…`).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_root_domain(raw: str) -> str:
    """Return a bare, lower-case, ASCII (punycode) host name, or raise
    ValueError with a message fit to show the user.

    Accepts and strips: a scheme, a path/query/fragment, a trailing dot.
    Rejects: ports, credentials, IP addresses, single-label names
    (`localhost`), wildcards, and anything that isn't a valid DNS name.
    """
    value = raw.strip()
    if not value:
        raise ValueError("enter a domain, e.g. app.example.com")

    if "://" in value:
        parts = urlsplit(value)
        if parts.username or parts.password:
            raise ValueError("enter just the domain, without a username or password")
        netloc = parts.netloc
    else:
        netloc = re.split(r"[/?#]", value, maxsplit=1)[0]

    if "@" in netloc:
        raise ValueError("enter just the domain, without a username or password")
    host = netloc
    if host.startswith("["):
        raise ValueError("enter a domain name, not an IP address")
    if ":" in host:
        raise ValueError(
            "enter the domain without a port (e.g. app.example.com, not app.example.com:8443)"
        )

    host = host.rstrip(".").lower()
    if not host:
        raise ValueError("enter a domain, e.g. app.example.com")
    if "*" in host:
        raise ValueError("enter one domain without wildcards; subdomains are covered automatically")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("enter a domain name, not an IP address")

    try:
        host = host.encode("idna").decode("ascii")  # münchen.de -> xn--mnchen-3ya.de
    except UnicodeError as exc:
        raise ValueError("that isn't a valid domain name") from exc

    if len(host) > 253:
        raise ValueError("domain is too long (max 253 characters)")
    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError(
            "enter a full domain such as app.example.com "
            "(single names like 'localhost' aren't scannable)"
        )
    if not all(_LABEL.match(label) for label in labels):
        raise ValueError("that isn't a valid domain name (letters, digits and hyphens only)")
    if labels[-1].isdigit():
        raise ValueError("that isn't a valid domain name")
    return host
