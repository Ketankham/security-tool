"""Who is calling.

The dashboard sits behind the Caddy sign-in proxy (per-person basic auth).
Caddy forwards each request to this API with two headers it sets itself,
replacing anything the client sent:

    X-Sentinel-User          the signed-in username
    X-Sentinel-Proxy-Secret  a shared secret only Caddy and this API know

The API trusts X-Sentinel-User only when the secret matches. The API port is
also reachable from other containers (and, on a misconfigured host, from
elsewhere), so a bare user header proves nothing: anyone who can reach the
port could type it. A user header that arrives without the right secret is
ignored (and logged), never believed.

For local development ``DEV_IDENTITY`` stands in for the proxy; it is refused
at startup when ENVIRONMENT=production (see main.create_app).
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Literal

import structlog
from fastapi import Request

from .config import Settings, get_settings

log = structlog.get_logger(__name__)

USER_HEADER = "x-sentinel-user"
SECRET_HEADER = "x-sentinel-proxy-secret"

# Same rule as infra/deploy/manage-users.sh, which is what creates the names.
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")

_MAX_IP_CHARS = 64
_MAX_UA_CHARS = 300


@dataclass(frozen=True)
class Identity:
    username: str
    source: Literal["proxy", "dev"]
    client_ip: str | None = None
    user_agent: str | None = None


def _secret_matches(presented: str | None, expected: str) -> bool:
    if not expected or presented is None:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _client_ip_from_proxy(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for", "")
    first = forwarded.split(",")[0].strip()
    if first:
        return first[:_MAX_IP_CHARS]
    return request.client.host[:_MAX_IP_CHARS] if request.client else None


def resolve_identity(request: Request, settings: Settings) -> Identity | None:
    """The verified identity of this request, or None."""
    user_header = request.headers.get(USER_HEADER)
    user_agent = (request.headers.get("user-agent") or "")[:_MAX_UA_CHARS] or None

    if _secret_matches(request.headers.get(SECRET_HEADER), settings.proxy_shared_secret):
        if user_header is not None and USERNAME_RE.fullmatch(user_header):
            return Identity(
                username=user_header,
                source="proxy",
                client_ip=_client_ip_from_proxy(request),
                user_agent=user_agent,
            )
        log.warning("identity.invalid_username", length=len(user_header or ""))
        return None

    if user_header is not None:
        # Someone sent a username without the proxy's secret: a request that
        # bypassed the sign-in proxy. Never trusted.
        log.warning("identity.untrusted_header", length=len(user_header))

    if settings.dev_identity and settings.environment != "production":
        return Identity(
            username=settings.dev_identity,
            source="dev",
            client_ip=request.client.host[:_MAX_IP_CHARS] if request.client else None,
            user_agent=user_agent,
        )
    return None


def get_identity(request: Request) -> Identity | None:
    """FastAPI dependency: the caller's verified identity, or None. (The
    middleware in main.py has usually resolved it already.)"""
    cached = getattr(request.state, "identity_resolved", False)
    if cached:
        identity: Identity | None = request.state.identity
        return identity
    return resolve_identity(request, get_settings())
