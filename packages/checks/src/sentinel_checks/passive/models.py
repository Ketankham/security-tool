"""Passive/config checks (docs/03-check-catalogue.md §1-3): read-only checks
that need nothing but ordinary GET/HEAD requests to the target's own hosts:
security headers, cookie flags, CORS, exposed files, TLS.

Every check returns ``PassiveCandidate``s. Like the authorization engine, a
check only *proposes*: the worker re-runs each candidate's ``reproduce``
twice (sentinel_checks.verification) and only a candidate that reproduces is
stored as ``confirmed``. Kept free of database imports like the other check
packages; apps/worker/passive_adapter.py turns candidates into Finding rows.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from sentinel_core.http_engine import EngineResponse, HttpEngine, ScopeViolation

# (level, message): feeds the scan's activity log.
LogFn = Callable[[str, str], None]


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """One stored request/response backing a finding."""

    transcript_id: str
    method: str
    url: str
    status_code: int | None
    role: str
    note: str


@dataclass(slots=True)
class PassiveCandidate:
    rule_id: str
    title: str
    severity: str  # critical | high | medium | low | info
    cwe: list[int]
    owasp: str | None
    origin: str  # scheme://host[:port]: the finding's identity within a scan
    subject: str  # what within the origin: a header, path or cookie group
    narrative: str
    remediation_summary: str
    remediation_steps: list[str]
    reproduction_curl: str
    reproduction_expect: str
    evidence: list[EvidenceRef] = field(default_factory=list)
    # Independently re-runs the probe and says whether the problem is still
    # there. None: it was observed once and can't be re-run (e.g. cookie flags
    # seen after a login), so it stays "probable".
    reproduce: Callable[[], Awaitable[bool]] | None = None


@dataclass(slots=True)
class PassiveContext:
    """What the checks may look at, and the one way they may make requests
    (through the scan's HttpEngine: scope-checked, rate-limited, recorded)."""

    http: HttpEngine
    # Hosts the crawl actually reached (scheme://host[:port]).
    origins: list[str]
    # Per origin, HTML pages (GET) the logged-out crawl reached; first is the
    # most representative (the root page when present).
    pages_by_origin: dict[str, list[str]]
    # Per origin, GET endpoints the pages called in the background (XHR/fetch).
    api_urls_by_origin: dict[str, list[str]]
    # Persona label -> cookies from its login (name/domain/flags only, never
    # values).
    persona_cookies: dict[str, list[dict[str, Any]]]
    log: LogFn
    # Gate for the few checks that open raw sockets (TLS): same scope rules
    # as HTTP.
    scope_allows: Callable[[str], bool] = lambda _url: True
    # Tests inject a context that trusts their own CA.
    tls_context_factory: Callable[[], Any] | None = None
    requests: int = 0
    # Origins that did not answer at all (set by the first check that looked):
    # the others skip them instead of retrying every probe against a dead host.
    unreachable: set[str] = field(default_factory=set)
    # Filled by the headers check, reused by the cookies check.
    page_responses: list[tuple[str, str, EngineResponse]] = field(default_factory=list)

    async def fetch(self, method: str, url: str, **kwargs: Any) -> EngineResponse | None:
        """A request that never raises: out-of-scope and unreachable URLs are
        logged and come back as None."""
        try:
            response = await self.http.request(method, url, **kwargs)
        except ScopeViolation as exc:
            self.log("info", f"Skipped {method} {url}: outside the scan's scope ({exc})")
            return None
        except ConnectionError as exc:
            self.log("warn", f"Could not reach {url}: {exc}")
            return None
        self.requests += 1
        return response


def hget(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def is_html(response: EngineResponse) -> bool:
    return "text/html" in (hget(response.headers, "content-type") or "").lower()


def origin_of(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def curl_for(url: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> str:
    """A copy-pasteable command that repeats the probe."""
    flags = "-sS -i" if method == "GET" else "-sS -I"
    parts = [f"curl {flags}"]
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    parts.append(f"'{url}'")
    return " ".join(parts)
