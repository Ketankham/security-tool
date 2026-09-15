"""HttpEngine: the single outbound choke point (docs/01-architecture.md §4.1
item 1).

Every request the platform ever makes to a target — recon probe, crawl
click, injection payload, authz replay — goes through here. That
concentration is deliberate: it's the one place we can guarantee scope
enforcement, rate limiting, and evidence recording happen for *every*
request, rather than trusting each of a dozen check modules to remember.

    engine = HttpEngine(scope_guard=..., rate_limiter=..., recorder=...,
                         target_id=target.id, scan_id=scan.id)
    resp = await engine.request("GET", url, persona=admin_session)
    if resp.status_code == 200 and CANARY in resp.text:
        ...

No caller ever needs httpx directly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import structlog

from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.scope_guard import (
    DestructiveActionGuard,
    ScopeDecision,
    ScopeGuard,
    ScopeVerdict,
)
from sentinel_core.transcript import RecordedRequest, RecordedResponse, TranscriptRecorder

from .errors import ScopeViolation
from .session import AnonymousSession, SessionState

log = structlog.get_logger(__name__)

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_RATE_LIMITED_STATUS_CODES = frozenset({429, 503})


@dataclass(frozen=True, slots=True)
class EngineResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    transcript_id: str
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class HttpEngine:
    def __init__(
        self,
        *,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter,
        recorder: TranscriptRecorder,
        target_id: str,
        scan_id: str,
        destructive_guard: DestructiveActionGuard | None = None,
        timeout_s: float = 20.0,
        max_retries: int = 2,
        user_agent: str = "SentinelScanner/0.1 (+https://example.invalid/about-our-scanner)",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._scope_guard = scope_guard
        self._rate_limiter = rate_limiter
        self._recorder = recorder
        self._target_id = target_id
        self._scan_id = scan_id
        self._destructive_guard = destructive_guard or DestructiveActionGuard()
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._user_agent = user_agent
        self._client = client or httpx.AsyncClient(
            follow_redirects=False, timeout=timeout_s, verify=True
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        persona: SessionState | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        link_text: str = "",
        skip_destructive_guard: bool = False,
    ) -> EngineResponse:
        persona = persona or AnonymousSession()
        method = method.upper()

        decision = self._scope_guard.evaluate(method=method, url=url)
        if not decision.allowed:
            log.warning(
                "scope_guard.blocked",
                target_id=self._target_id,
                scan_id=self._scan_id,
                method=method,
                url=url,
                reason=decision.reason,
            )
            raise ScopeViolation(decision)

        if not skip_destructive_guard:
            check = self._destructive_guard.check(method=method, url=url, link_text=link_text)
            if check.is_suspect:
                log.warning(
                    "destructive_guard.blocked",
                    target_id=self._target_id,
                    scan_id=self._scan_id,
                    method=method,
                    url=url,
                    reason=check.reason,
                )
                raise ScopeViolation(
                    ScopeDecision(
                        verdict=ScopeVerdict.BLOCKED_METHOD,
                        reason=f"Destructive-action guard: {check.reason}",
                    )
                )

        await self._rate_limiter.acquire(self._target_id)

        request_headers = {
            "User-Agent": self._user_agent,
            **persona.extra_headers(),
            **(headers or {}),
        }
        # Built as a literal Cookie header rather than passed via httpx's
        # per-request `cookies=` kwarg: the client is shared across personas
        # in one HttpEngine, and httpx's per-request cookies merge into (and
        # persist in) the client's shared jar — exactly the cross-persona
        # contamination this engine must never allow.
        persona_cookies = persona.cookies()
        if persona_cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in persona_cookies.items())
            request_headers.setdefault("Cookie", cookie_header)

        req = RecordedRequest(method=method, url=url, headers=dict(request_headers), body=body)

        response_obj: RecordedResponse | None = None
        error: str | None = None
        attempt = 0
        max_attempts = 1 + (self._max_retries if method in _IDEMPOTENT_METHODS else 0)

        while attempt < max_attempts:
            attempt += 1
            start = time.monotonic()
            try:
                httpx_response = await self._client.request(
                    method, url, headers=request_headers, content=body
                )
                elapsed_ms = (time.monotonic() - start) * 1000
                response_obj = RecordedResponse(
                    status_code=httpx_response.status_code,
                    headers=dict(httpx_response.headers),
                    body=httpx_response.content,
                    elapsed_ms=elapsed_ms,
                )

                if httpx_response.status_code in _RATE_LIMITED_STATUS_CODES:
                    await self._rate_limiter.report_backpressure(
                        self._target_id, reason=f"HTTP {httpx_response.status_code}"
                    )
                    if attempt < max_attempts:
                        continue
                else:
                    await self._rate_limiter.report_success(self._target_id)
                break
            except httpx.TimeoutException as exc:
                error = f"timeout: {exc}"
                if attempt >= max_attempts:
                    break
            except httpx.TransportError as exc:
                error = f"transport_error: {exc}"
                if attempt >= max_attempts:
                    break

        transcript_id = await self._recorder.record(
            scan_id=self._scan_id,
            persona_id=getattr(persona, "persona_id", None),
            request=req,
            response=response_obj,
            error=error if response_obj is None else None,
        )

        if response_obj is None:
            raise ConnectionError(f"Request to {url} failed after {attempt} attempt(s): {error}")

        return EngineResponse(
            status_code=response_obj.status_code,
            headers=response_obj.headers,
            body=response_obj.body or b"",
            elapsed_ms=response_obj.elapsed_ms,
            transcript_id=transcript_id,
            url=url,
        )
