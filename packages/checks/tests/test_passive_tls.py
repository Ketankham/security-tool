"""TLS checks against real TLS servers with real certificates, issued by a
throw-away CA that the test trusts (so expiry, host name and trust failures
are each reproduced for real, not simulated)."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import socket
import ssl
from pathlib import Path

import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fakeredis.aioredis import FakeRedis
from sentinel_checks.passive import PassiveContext
from sentinel_checks.passive.tls import check_tls
from sentinel_checks.verification import verify_candidate
from sentinel_core.http_engine import HttpEngine
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.transcript import LocalTranscriptStore, TranscriptRecorder
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

NOW = dt.datetime.now(dt.UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


class Authority:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Test CA"))
            .issuer_name(_name("Test CA"))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=400))
            .not_valid_after(NOW + dt.timedelta(days=400))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )

    def leaf(self, *, dns: str | None, ip: str | None, starts: dt.datetime, ends: dt.datetime):
        key = ec.generate_private_key(ec.SECP256R1())
        names: list[x509.GeneralName] = []
        if dns:
            names.append(x509.DNSName(dns))
        if ip:
            names.append(x509.IPAddress(ipaddress.ip_address(ip)))
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(dns or ip or "leaf"))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(starts)
            .not_valid_after(ends)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        return key, cert


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _serve_tls(tmp_path: Path, key, cert) -> tuple[uvicorn.Server, asyncio.Task, int]:
    key_file, cert_file = tmp_path / "k.pem", tmp_path / "c.pem"
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(_pem(cert))
    port = _free_port()
    app = Starlette(routes=[Route("/", lambda r: PlainTextResponse("hi"))])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            ssl_keyfile=str(key_file),
            ssl_certfile=str(cert_file),
        )
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, task, port


def _ctx(tmp_path: Path, port: int, ca: Authority | None, *, host: str = "127.0.0.1"):
    cafile = tmp_path / "ca.pem"
    if ca is not None:
        cafile.write_bytes(_pem(ca.cert))
    engine = HttpEngine(
        scope_guard=ScopeGuard(allowed_hosts={host}, target_ownership_verified=True),
        rate_limiter=RateLimiter(FakeRedis(), default_rate_per_sec=1000, burst=1000),
        recorder=TranscriptRecorder(LocalTranscriptStore(tmp_path / "t")),
        target_id="t",
        scan_id="s",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(404)), follow_redirects=False
        ),
    )
    origin = f"https://{host}:{port}"
    return PassiveContext(
        http=engine,
        origins=[origin],
        pages_by_origin={origin: [origin + "/"]},
        api_urls_by_origin={},
        persona_cookies={},
        log=lambda *_: None,
        tls_context_factory=(lambda: ssl.create_default_context(cafile=str(cafile)))
        if ca is not None
        else None,
    )


async def _run(tmp_path: Path, *, ca_trusted: bool, **leaf_kwargs):
    ca = Authority()
    key, cert = ca.leaf(**leaf_kwargs)
    server, task, port = await _serve_tls(tmp_path, key, cert)
    try:
        ctx = _ctx(tmp_path, port, ca if ca_trusted else None)
        return await check_tls(ctx)
    finally:
        server.should_exit = True
        await task


GOOD = dict(
    dns=None, ip="127.0.0.1", starts=NOW - dt.timedelta(days=1), ends=NOW + dt.timedelta(days=90)
)


async def test_a_valid_certificate_is_clean(tmp_path):
    found = await _run(tmp_path, ca_trusted=True, **GOOD)
    assert [c.rule_id for c in found] == []


async def test_a_certificate_about_to_expire_is_flagged(tmp_path):
    found = await _run(tmp_path, ca_trusted=True, **{**GOOD, "ends": NOW + dt.timedelta(days=5)})
    assert [c.rule_id for c in found] == ["tls.cert_expiring"]
    assert "5 day" in found[0].narrative or "4 day" in found[0].narrative
    assert found[0].severity == "medium"


async def test_an_expired_certificate_is_flagged(tmp_path):
    found = await _run(
        tmp_path,
        ca_trusted=True,
        **{**GOOD, "starts": NOW - dt.timedelta(days=60), "ends": NOW - dt.timedelta(days=2)},
    )
    assert [c.rule_id for c in found] == ["tls.cert_expired"]
    assert found[0].severity == "high"
    assert "certificate has expired" in found[0].narrative or "expired" in found[0].narrative


async def test_a_certificate_for_another_host_name_is_flagged(tmp_path):
    found = await _run(tmp_path, ca_trusted=True, **{**GOOD, "ip": None, "dns": "other.test"})
    assert [c.rule_id for c in found] == ["tls.cert_hostname_mismatch"]


async def test_an_untrusted_certificate_is_flagged(tmp_path):
    found = await _run(tmp_path, ca_trusted=False, **GOOD)  # the default trust store lacks our CA
    assert [c.rule_id for c in found] == ["tls.cert_untrusted"]
    assert found[0].severity == "high"
    assert "openssl s_client" in found[0].reproduction_curl


async def test_findings_reproduce_while_the_problem_exists(tmp_path):
    ca = Authority()
    key, cert = ca.leaf(
        **{**GOOD, "ends": NOW - dt.timedelta(days=1), "starts": NOW - dt.timedelta(days=30)}
    )
    server, task, port = await _serve_tls(tmp_path, key, cert)
    try:
        found = await check_tls(_ctx(tmp_path, port, ca))
        assert found and (await verify_candidate(found[0].reproduce)).passed
    finally:
        server.should_exit = True
        await task


async def test_a_host_outside_the_scope_is_never_connected_to(tmp_path):
    ca = Authority()
    key, cert = ca.leaf(**GOOD)
    server, task, port = await _serve_tls(tmp_path, key, cert)
    try:
        ctx = _ctx(tmp_path, port, ca)
        ctx.scope_allows = lambda _url: False
        assert await check_tls(ctx) == []
    finally:
        server.should_exit = True
        await task


async def test_a_plain_http_site_without_https_is_flagged(tmp_path):
    port = _free_port()  # nothing listens on this port, nor on 443
    ctx = _ctx(tmp_path, port, None)
    ctx.origins = [f"http://127.0.0.1:{port}"]
    found = await check_tls(ctx)
    assert [c.rule_id for c in found] == ["tls.http_only"]
    assert (await verify_candidate(found[0].reproduce)).passed


async def test_a_dead_host_is_logged_not_fatal(tmp_path):
    port = _free_port()
    ctx = _ctx(tmp_path, port, None)
    logs: list[tuple[str, str]] = []
    ctx.log = lambda level, message: logs.append((level, message))
    assert await check_tls(ctx) == []
    assert any(level == "warn" and "could not connect" in m for level, m in logs)
