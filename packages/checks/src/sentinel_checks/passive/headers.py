"""Security response headers (docs/03 §1).

Each rule is a pure predicate over one response, so the rules are unit
testable and ``reproduce`` can re-evaluate exactly the same condition.
Only HTML pages answering 200 are judged: a redirect or an error page
legitimately carries different headers. A header missing on some pages but
present on others is reported once per site, listing the pages that lack it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from sentinel_core.http_engine import EngineResponse

from .models import (
    EvidenceRef,
    PassiveCandidate,
    PassiveContext,
    curl_for,
    hget,
    is_html,
    origin_of,
)

_VERSION_RE = re.compile(r"\d+\.\d+")
_HSTS_MIN_AGE = 15_552_000  # 180 days


@dataclass(frozen=True, slots=True)
class HeaderRule:
    rule_id: str
    subject: str  # header name, or a short label
    title: str
    severity: str
    cwe: list[int]
    https_only: bool
    # True when the response violates the rule.
    violates: Callable[[dict[str, str]], bool]
    what: str  # "what is wrong", for the narrative
    fix: str
    steps: list[str]


def _missing(name: str) -> Callable[[dict[str, str]], bool]:
    return lambda h: hget(h, name) is None


def _csp_missing(h: dict[str, str]) -> bool:
    return hget(h, "content-security-policy") is None and (
        hget(h, "content-security-policy-report-only") is None
    )


def _csp_report_only(h: dict[str, str]) -> bool:
    return hget(h, "content-security-policy") is None and (
        hget(h, "content-security-policy-report-only") is not None
    )


def _clickjacking(h: dict[str, str]) -> bool:
    csp = (hget(h, "content-security-policy") or "").lower()
    return hget(h, "x-frame-options") is None and "frame-ancestors" not in csp


def _nosniff_missing(h: dict[str, str]) -> bool:
    return (hget(h, "x-content-type-options") or "").strip().lower() != "nosniff"


def _hsts_weak(h: dict[str, str]) -> bool:
    value = hget(h, "strict-transport-security")
    if value is None:
        return False  # absence is the other rule's finding
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return match is None or int(match.group(1)) < _HSTS_MIN_AGE


def _version_disclosure(h: dict[str, str]) -> bool:
    return any(
        _VERSION_RE.search(hget(h, name) or "")
        for name in ("server", "x-powered-by", "x-aspnet-version")
    )


RULES: list[HeaderRule] = [
    HeaderRule(
        "headers.hsts_missing",
        "Strict-Transport-Security",
        "HSTS header missing",
        "low",
        [319],
        True,
        _missing("strict-transport-security"),
        "The Strict-Transport-Security header is not sent, so browsers will still try plain "
        "HTTP first and a network attacker can downgrade the first visit.",
        "Send Strict-Transport-Security on every HTTPS response.",
        [
            "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Make sure every subdomain works over HTTPS before adding includeSubDomains.",
        ],
    ),
    HeaderRule(
        "headers.hsts_weak",
        "Strict-Transport-Security",
        "HSTS max-age is too short",
        "info",
        [319],
        True,
        _hsts_weak,
        "Strict-Transport-Security is sent but its max-age is under 180 days, so browsers "
        "forget the HTTPS-only rule quickly.",
        "Raise max-age to at least one year.",
        ["Set: Strict-Transport-Security: max-age=31536000; includeSubDomains"],
    ),
    HeaderRule(
        "headers.csp_missing",
        "Content-Security-Policy",
        "Content-Security-Policy header missing",
        "low",
        [1021, 693],
        False,
        _csp_missing,
        "No Content-Security-Policy is sent. A CSP is the main browser-side defence that "
        "limits the damage of a cross-site scripting bug.",
        "Add a Content-Security-Policy that only allows the scripts, styles and frames the "
        "site actually uses.",
        [
            "Start in report-only mode: Content-Security-Policy-Report-Only: default-src 'self'",
            "Fix what it reports, then switch to the enforcing Content-Security-Policy header.",
            "Avoid 'unsafe-inline' and 'unsafe-eval' in script-src.",
        ],
    ),
    HeaderRule(
        "headers.csp_report_only",
        "Content-Security-Policy",
        "Content-Security-Policy is report-only (not enforced)",
        "info",
        [693],
        False,
        _csp_report_only,
        "Only Content-Security-Policy-Report-Only is sent: violations are reported but "
        "nothing is blocked.",
        "Once the reports are clean, switch to the enforcing Content-Security-Policy header.",
        ["Rename the header from Content-Security-Policy-Report-Only to Content-Security-Policy."],
    ),
    HeaderRule(
        "headers.clickjacking",
        "X-Frame-Options",
        "Page can be framed by other sites (clickjacking)",
        "low",
        [1021],
        False,
        _clickjacking,
        "Neither X-Frame-Options nor a CSP frame-ancestors rule is sent, so another site "
        "can load this page in a hidden frame and trick users into clicking on it.",
        "Forbid framing, or allow only your own sites.",
        [
            "Add: Content-Security-Policy: frame-ancestors 'self'",
            "Optionally also add: X-Frame-Options: SAMEORIGIN (for old browsers).",
        ],
    ),
    HeaderRule(
        "headers.nosniff_missing",
        "X-Content-Type-Options",
        "X-Content-Type-Options: nosniff missing",
        "low",
        [693],
        False,
        _nosniff_missing,
        "X-Content-Type-Options: nosniff is not sent, so browsers may guess a file's type "
        "and run content (for example an uploaded file) as a script.",
        "Send X-Content-Type-Options: nosniff.",
        ["Add the header: X-Content-Type-Options: nosniff"],
    ),
    HeaderRule(
        "headers.referrer_policy_missing",
        "Referrer-Policy",
        "Referrer-Policy header missing",
        "info",
        [200],
        False,
        _missing("referrer-policy"),
        "No Referrer-Policy is sent, so the full URL of these pages (which can contain "
        "ids or tokens) may be passed to other sites when users follow links.",
        "Send a Referrer-Policy such as strict-origin-when-cross-origin.",
        ["Add the header: Referrer-Policy: strict-origin-when-cross-origin"],
    ),
    HeaderRule(
        "headers.permissions_policy_missing",
        "Permissions-Policy",
        "Permissions-Policy header missing",
        "info",
        [693],
        False,
        _missing("permissions-policy"),
        "No Permissions-Policy is sent, so embedded content may request powerful browser "
        "features (camera, microphone, location) unless the browser's defaults stop it.",
        "Send a Permissions-Policy that switches off the features the site does not use.",
        ["Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()"],
    ),
    HeaderRule(
        "headers.version_disclosure",
        "Server",
        "Server software and version disclosed",
        "info",
        [200],
        False,
        _version_disclosure,
        "The Server, X-Powered-By or X-AspNet-Version header reveals the software and its "
        "version, which helps an attacker pick known exploits.",
        "Remove the version from these headers (or the headers themselves).",
        [
            "Nginx: server_tokens off;  Apache: ServerTokens Prod and ServerSignature Off.",
            "Remove X-Powered-By (PHP: expose_php = Off; Express: app.disable('x-powered-by')).",
        ],
    ),
]


def _shown(headers: dict[str, str], names: tuple[str, ...]) -> str:
    present = [f"{n}: {hget(headers, n)}" for n in names if hget(headers, n) is not None]
    return "; ".join(present) if present else "(none of these headers)"


_RELATED = {
    "headers.csp_missing": ("content-security-policy", "content-security-policy-report-only"),
    "headers.clickjacking": ("x-frame-options", "content-security-policy"),
    "headers.version_disclosure": ("server", "x-powered-by", "x-aspnet-version"),
}


async def check_security_headers(ctx: PassiveContext) -> list[PassiveCandidate]:
    candidates: list[PassiveCandidate] = []
    for origin in ctx.origins:
        is_https = origin.startswith("https://")
        urls = (ctx.pages_by_origin.get(origin) or [f"{origin}/"])[:4]
        html: list[tuple[str, EngineResponse]] = []
        answered = False
        for url in urls:
            response = await ctx.fetch("GET", url)
            if response is None:
                continue
            answered = True
            ctx.page_responses.append((origin, url, response))
            if response.status_code == 200 and is_html(response):
                html.append((url, response))
            else:
                ctx.log(
                    "info",
                    f"Header check: {url} answered {response.status_code} "
                    f"({'HTML' if is_html(response) else 'not HTML'}), so it is not judged.",
                )
        if not answered:
            ctx.unreachable.add(origin)
            ctx.log(
                "warn",
                f"{origin} did not answer, so the remaining passive checks skip it.",
            )
            continue
        if not html:
            ctx.log(
                "warn",
                f"Header check: no HTML page on {origin} answered 200, so its security "
                "headers could not be judged.",
            )
            continue

        found = 0
        for rule in RULES:
            if rule.https_only and not is_https:
                continue
            violating = [(u, r) for u, r in html if rule.violates(r.headers)]
            if not violating:
                continue
            found += 1
            first_url, first = violating[0]
            related = _RELATED.get(rule.rule_id, (rule.subject,))
            pages = ", ".join(u for u, _ in violating[:5])
            narrative = (
                f"{rule.what} Seen on {len(violating)} of {len(html)} page(s) checked on "
                f"{origin}: {pages}. What the server sent: {_shown(first.headers, related)}."
            )

            def make_reproduce(rule: HeaderRule = rule, url: str = first_url):
                async def reproduce() -> bool:
                    again = await ctx.fetch("GET", url)
                    return (
                        again is not None
                        and again.status_code == 200
                        and rule.violates(again.headers)
                    )

                return reproduce

            candidates.append(
                PassiveCandidate(
                    rule_id=rule.rule_id,
                    title=f"{rule.title} ({origin_of(first_url).split('://', 1)[1]})",
                    severity=rule.severity,
                    cwe=rule.cwe,
                    owasp="A05:2021",
                    origin=origin,
                    subject=rule.subject,
                    narrative=narrative,
                    remediation_summary=rule.fix,
                    remediation_steps=rule.steps,
                    reproduction_curl=curl_for(first_url),
                    reproduction_expect=(
                        f"Look at the response headers: {rule.subject} should be present and "
                        "correct, but is not."
                    ),
                    evidence=[
                        EvidenceRef(
                            transcript_id=first.transcript_id,
                            method="GET",
                            url=first_url,
                            status_code=first.status_code,
                            role="response-headers",
                            note=f"Response headers of {first_url}",
                        )
                    ],
                    reproduce=make_reproduce(),
                )
            )
        ctx.log(
            "info",
            f"Header check on {origin}: {len(html)} page(s) judged, {found} issue(s) found.",
        )
    return candidates
