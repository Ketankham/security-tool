"""TLS and transport (docs/03 §1): certificate validity, expiry, legacy
protocol versions, and whether plain HTTP is served or redirected.

The certificate and protocol probes open a plain TLS connection to the
host's own port (a handful of connections per host), only for hosts the scope
rules allow. A TLS handshake is not an HTTP request, so there is no stored
transcript: evidence is the narrative and an ``openssl`` command to repeat it.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
import warnings
from typing import Any
from urllib.parse import urlsplit

from .models import PassiveCandidate, PassiveContext, curl_for, hget

_EXPIRY_WARN_DAYS = 14
# OpenSSL X509 verify codes.
_EXPIRED = {10}
_NOT_YET_VALID = {9}
_HOSTNAME = {62, 64}
_UNTRUSTED = {2, 3, 18, 19, 20, 21}


def _openssl_cmd(host: str, port: int) -> str:
    return (
        f"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>/dev/null "
        "| openssl x509 -noout -subject -issuer -dates"
    )


async def probe_certificate(
    host: str, port: int, context_factory: Any | None = None
) -> dict[str, Any]:
    """{'status': 'ok', 'days_left', 'version'} | {'status': 'verify_failed',
    'code', 'message'} | {'status': 'unreachable', 'message'}"""
    ssl_ctx = context_factory() if context_factory else ssl.create_default_context()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host), timeout=10
        )
    except ssl.SSLCertVerificationError as exc:
        return {"status": "verify_failed", "code": exc.verify_code, "message": exc.verify_message}
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return {"status": "unreachable", "message": str(exc)[:200]}
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() if ssl_object else {}
        version = ssl_object.version() if ssl_object else None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    not_after = cert.get("notAfter") if cert else None
    days_left = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400 if not_after else None
    return {"status": "ok", "days_left": days_left, "version": version}


async def legacy_protocols_accepted(host: str, port: int) -> list[str]:
    """TLS 1.0 / 1.1 versions the server still completes a handshake for. A
    probe the local OpenSSL build refuses to even attempt proves nothing, so
    it is silently skipped (no finding)."""
    accepted: list[str] = []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                # Selecting a deprecated TLS version is the whole point here.
                warnings.simplefilter("ignore", DeprecationWarning)
                ssl_ctx.minimum_version = version
                ssl_ctx.maximum_version = version
            ssl_ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            continue
        try:
            _r, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host), timeout=8
            )
        except (OSError, TimeoutError, ssl.SSLError):
            continue
        accepted.append(name)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return accepted


def _candidate(
    *,
    rule_id: str,
    title: str,
    severity: str,
    cwe: list[int],
    origin: str,
    host: str,
    port: int,
    narrative: str,
    fix: str,
    steps: list[str],
    reproduce: Any,
    curl: str | None = None,
) -> PassiveCandidate:
    return PassiveCandidate(
        rule_id=rule_id,
        title=f"{title} ({host})",
        severity=severity,
        cwe=cwe,
        owasp="A02:2021",
        origin=origin,
        subject=rule_id,
        narrative=narrative,
        remediation_summary=fix,
        remediation_steps=steps,
        reproduction_curl=curl or _openssl_cmd(host, port),
        reproduction_expect="The output (or the connection error) shows the problem described.",
        evidence=[],
        reproduce=reproduce,
    )


async def check_tls(ctx: PassiveContext) -> list[PassiveCandidate]:
    candidates: list[PassiveCandidate] = []
    checked = 0
    for origin in ctx.origins:
        parts = urlsplit(origin)
        host = parts.hostname or ""
        is_https = parts.scheme == "https"
        port = parts.port or (443 if is_https else 80)

        if not is_https:
            # Served over plain HTTP: does the same host offer HTTPS at all?
            if ctx.scope_allows(f"https://{host}/"):
                cert = await probe_certificate(host, 443, ctx.tls_context_factory)
                checked += 1
                if cert["status"] == "unreachable":

                    async def http_only_still(host: str = host) -> bool:
                        again = await probe_certificate(host, 443, ctx.tls_context_factory)
                        return again["status"] == "unreachable"

                    candidates.append(
                        _candidate(
                            rule_id="tls.http_only",
                            title="Site is served over plain HTTP only",
                            severity="medium",
                            cwe=[319],
                            origin=origin,
                            host=host,
                            port=port,
                            narrative=(
                                f"{origin} is served over unencrypted HTTP and the host does "
                                "not accept HTTPS connections on port 443. Logins, cookies and "
                                "page content can be read or changed by anyone on the network "
                                f"path. (HTTPS connection result: {cert['message']})"
                            ),
                            fix="Serve the site over HTTPS and redirect HTTP to it.",
                            steps=[
                                "Get a certificate (Let's Encrypt is free) and enable HTTPS.",
                                "Redirect all HTTP requests to HTTPS and send HSTS.",
                            ],
                            reproduce=http_only_still,
                            curl=curl_for(f"https://{host}/"),
                        )
                    )
            continue

        if not ctx.scope_allows(f"https://{host}/"):
            ctx.log("info", f"TLS check skipped for {host}: outside the scan's scope.")
            continue

        cert = await probe_certificate(host, port, ctx.tls_context_factory)
        checked += 1
        status = cert["status"]
        if status == "unreachable":
            ctx.log("warn", f"TLS check: could not connect to {host}:{port} ({cert['message']}).")
        elif status == "verify_failed":
            code = cert["code"]
            message = cert["message"]

            def make_reproduce(host: str = host, port: int = port, code: int = code):
                async def reproduce() -> bool:
                    again = await probe_certificate(host, port, ctx.tls_context_factory)
                    return again["status"] == "verify_failed" and again["code"] == code

                return reproduce

            if code in _EXPIRED:
                rule, title, cwe = "tls.cert_expired", "TLS certificate has expired", [298]
            elif code in _NOT_YET_VALID:
                rule, title, cwe = (
                    "tls.cert_not_yet_valid",
                    "TLS certificate is not valid yet",
                    [298],
                )
            elif code in _HOSTNAME:
                rule, title, cwe = (
                    "tls.cert_hostname_mismatch",
                    "TLS certificate is for a different host name",
                    [297],
                )
            elif code in _UNTRUSTED:
                rule, title, cwe = (
                    "tls.cert_untrusted",
                    "TLS certificate is not trusted (self-signed or incomplete chain)",
                    [295],
                )
            else:
                rule, title, cwe = "tls.cert_invalid", "TLS certificate failed validation", [295]
            candidates.append(
                _candidate(
                    rule_id=rule,
                    title=title,
                    severity="high",
                    cwe=cwe,
                    origin=origin,
                    host=host,
                    port=port,
                    narrative=(
                        f"Browsers will warn visitors or refuse to connect to {host}: "
                        f"certificate validation failed with '{message}' (OpenSSL code {code})."
                    ),
                    fix="Install a valid certificate for this exact host name, with its full "
                    "chain.",
                    steps=[
                        "Renew or replace the certificate (certbot renews automatically).",
                        "Install the intermediate certificates (full chain), not just the leaf.",
                        "Check that the certificate lists this host name (www. vs apex).",
                    ],
                    reproduce=make_reproduce(),
                )
            )
        else:
            days_left = cert.get("days_left")
            if days_left is not None and days_left <= _EXPIRY_WARN_DAYS:

                async def expiring_still(host: str = host, port: int = port) -> bool:
                    again = await probe_certificate(host, port, ctx.tls_context_factory)
                    left = again.get("days_left")
                    return (
                        again["status"] == "ok" and left is not None and left <= _EXPIRY_WARN_DAYS
                    )

                candidates.append(
                    _candidate(
                        rule_id="tls.cert_expiring",
                        title="TLS certificate expires soon",
                        severity="medium",
                        cwe=[298],
                        origin=origin,
                        host=host,
                        port=port,
                        narrative=(
                            f"The certificate for {host} expires in {days_left:.0f} day(s). "
                            "When it does, browsers will block the site."
                        ),
                        fix="Renew the certificate now and automate renewal.",
                        steps=[
                            "Renew the certificate.",
                            "Set up automatic renewal (certbot, your host's managed certificates) "
                            "and an expiry alert.",
                        ],
                        reproduce=expiring_still,
                    )
                )

            legacy = await legacy_protocols_accepted(host, port)
            if legacy:

                async def legacy_still(host: str = host, port: int = port) -> bool:
                    return bool(await legacy_protocols_accepted(host, port))

                candidates.append(
                    _candidate(
                        rule_id="tls.weak_protocol",
                        title="Outdated TLS versions are accepted",
                        severity="medium",
                        cwe=[326],
                        origin=origin,
                        host=host,
                        port=port,
                        narrative=(
                            f"{host} still completes a handshake using {' and '.join(legacy)}, "
                            "which have known weaknesses and are disabled in modern browsers."
                        ),
                        fix="Allow only TLS 1.2 and TLS 1.3.",
                        steps=[
                            "Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
                            "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
                            "Managed hosts/CDNs: set the minimum TLS version to 1.2.",
                        ],
                        reproduce=legacy_still,
                        curl=f"openssl s_client -connect {host}:{port} -tls1 </dev/null",
                    )
                )

        # Plain HTTP on the same host: served, or redirected to HTTPS?
        if port == 443:
            http_url = f"http://{host}/"
            plain = await ctx.fetch("GET", http_url)
            if plain is not None and plain.status_code == 200:

                async def still_plain(url: str = http_url) -> bool:
                    again = await ctx.fetch("GET", url)
                    return again is not None and again.status_code == 200

                candidates.append(
                    _candidate(
                        rule_id="tls.no_https_redirect",
                        title="HTTP is served instead of redirecting to HTTPS",
                        severity="low",
                        cwe=[319],
                        origin=origin,
                        host=host,
                        port=80,
                        narrative=(
                            f"{http_url} answers 200 over plain HTTP instead of redirecting to "
                            f"HTTPS (Location header: {hget(plain.headers, 'location')})."
                        ),
                        fix="Redirect all HTTP requests to HTTPS.",
                        steps=[
                            "Nginx: return 301 https://$host$request_uri; in the port 80 server.",
                            "Then send HSTS so browsers stop trying HTTP.",
                        ],
                        reproduce=still_plain,
                        curl=curl_for(http_url),
                    )
                )
    ctx.log("info", f"TLS check: {checked} host(s) examined, {len(candidates)} issue(s) found.")
    return candidates
