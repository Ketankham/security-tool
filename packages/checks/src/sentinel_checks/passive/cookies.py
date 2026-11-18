"""Cookie flags (docs/03 §3).

Two sources: ``Set-Cookie`` headers on the pages the header check already
fetched (re-checkable, so they can be confirmed), and the cookies each login
produced (flags as the browser stored them; seen once, so "probable").
Cookie *values* are never read into findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import EvidenceRef, PassiveCandidate, PassiveContext, curl_for

_SESSION_LIKE = re.compile(r"(?i)(sess|sid|auth|token|jwt|login|remember|access|refresh)")
_CSRF_LIKE = re.compile(r"(?i)(csrf|xsrf)")


@dataclass(frozen=True, slots=True)
class CookieFlags:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None  # lax | strict | none | None (not set)


def parse_set_cookie(header: str) -> CookieFlags | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    attrs = {
        p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "")
        for p in parts[1:]
    }
    same_site = attrs.get("samesite")
    return CookieFlags(
        name=name,
        secure="secure" in attrs,
        http_only="httponly" in attrs,
        same_site=same_site.lower() if same_site else None,
    )


def is_session_like(name: str) -> bool:
    return bool(_SESSION_LIKE.search(name)) and not _CSRF_LIKE.search(name)


@dataclass(frozen=True, slots=True)
class _Problem:
    rule_id: str
    title: str
    severity: str
    cwe: list[int]
    what: str
    fix: str
    steps: list[str]


_MISSING_SECURE = _Problem(
    "cookies.missing_secure",
    "Cookie sent without the Secure flag",
    "low",
    [614],
    "These cookies are set without the Secure flag, so the browser will also send them over "
    "plain HTTP, where they can be read on the network.",
    "Mark every cookie Secure on an HTTPS site.",
    ["Add the Secure attribute to Set-Cookie (most frameworks have a 'secure cookies' setting)."],
)
_MISSING_HTTPONLY = _Problem(
    "cookies.missing_httponly",
    "Session cookie readable by JavaScript (no HttpOnly)",
    "medium",
    [1004],
    "These session-like cookies are set without HttpOnly, so any script running on the page "
    "(including an injected one) can read them and take over the session.",
    "Mark session cookies HttpOnly.",
    ["Add the HttpOnly attribute to the session cookie (framework setting: 'httpOnly: true')."],
)
_SAMESITE_NONE = _Problem(
    "cookies.samesite_none",
    "Session cookie sent on cross-site requests (SameSite=None)",
    "low",
    [1275],
    "These session-like cookies use SameSite=None, so browsers attach them to requests "
    "started by other sites, which makes cross-site request forgery easier.",
    "Use SameSite=Lax (or Strict) unless cross-site use is genuinely needed.",
    ["Set the SameSite attribute to Lax on the session cookie."],
)


def _problems(cookie: CookieFlags, *, https: bool) -> list[_Problem]:
    found: list[_Problem] = []
    if https and not cookie.secure:
        found.append(_MISSING_SECURE)
    if is_session_like(cookie.name) and not cookie.http_only:
        found.append(_MISSING_HTTPONLY)
    if is_session_like(cookie.name) and cookie.same_site == "none":
        found.append(_SAMESITE_NONE)
    return found


def _severity(problem: _Problem, names: list[str]) -> str:
    # A missing Secure flag matters more on a session cookie.
    if problem is _MISSING_SECURE and any(is_session_like(n) for n in names):
        return "medium"
    return problem.severity


async def check_cookies(ctx: PassiveContext) -> list[PassiveCandidate]:
    candidates: list[PassiveCandidate] = []
    seen_cookies = 0

    # 1) Set-Cookie headers on the pages already fetched (re-checkable).
    grouped: dict[tuple[str, str], list[tuple[str, str, str, int, CookieFlags]]] = {}
    for origin, url, response in ctx.page_responses:
        for raw in response.set_cookies:
            cookie = parse_set_cookie(raw)
            if cookie is None:
                continue
            seen_cookies += 1
            for problem in _problems(cookie, https=origin.startswith("https://")):
                grouped.setdefault((origin, problem.rule_id), []).append(
                    (url, response.transcript_id, cookie.name, response.status_code, cookie)
                )
    problems_by_id = {p.rule_id: p for p in (_MISSING_SECURE, _MISSING_HTTPONLY, _SAMESITE_NONE)}
    for (origin, rule_id), hits in grouped.items():
        problem = problems_by_id[rule_id]
        names = sorted({h[2] for h in hits})
        first_url, transcript_id, _, status, _ = hits[0]

        def make_reproduce(
            url: str = first_url,
            names: list[str] = names,
            rule_id: str = rule_id,
            origin: str = origin,
        ):
            async def reproduce() -> bool:
                again = await ctx.fetch("GET", url)
                if again is None:
                    return False
                for raw in again.set_cookies:
                    cookie = parse_set_cookie(raw)
                    if (
                        cookie
                        and cookie.name in names
                        and any(
                            p.rule_id == rule_id
                            for p in _problems(cookie, https=origin.startswith("https://"))
                        )
                    ):
                        return True
                return False

            return reproduce

        candidates.append(
            PassiveCandidate(
                rule_id=problem.rule_id,
                title=f"{problem.title} ({origin.split('://', 1)[1]})",
                severity=_severity(problem, names),
                cwe=problem.cwe,
                owasp="A05:2021",
                origin=origin,
                subject=",".join(names),
                narrative=f"{problem.what} Cookies: {', '.join(names)}. First seen on {first_url}.",
                remediation_summary=problem.fix,
                remediation_steps=problem.steps,
                reproduction_curl=curl_for(first_url),
                reproduction_expect=(
                    f"In the Set-Cookie header(s), the cookie(s) {', '.join(names)} "
                    "are missing the attribute described above."
                ),
                evidence=[
                    EvidenceRef(
                        transcript_id=transcript_id,
                        method="GET",
                        url=first_url,
                        status_code=status,
                        role="set-cookie-headers",
                        note=f"Set-Cookie headers of {first_url}",
                    )
                ],
                reproduce=make_reproduce(),
            )
        )

    # 2) Cookies as stored after each login (seen once: probable).
    for label, cookies in ctx.persona_cookies.items():
        by_problem: dict[tuple[str, str], list[str]] = {}
        for raw in cookies:
            domain = str(raw.get("domain", "")).lstrip(".")
            matched = next(
                (
                    o
                    for o in ctx.origins
                    if (urlsplit(o).hostname or "").endswith(domain) and domain
                ),
                None,
            )
            if matched is None:
                continue
            origin_of_cookie: str = matched
            seen_cookies += 1
            persona_same_site = str(raw.get("sameSite", "")).lower() or None
            cookie = CookieFlags(
                name=str(raw.get("name", "")),
                secure=bool(raw.get("secure")),
                http_only=bool(raw.get("httpOnly")),
                same_site=persona_same_site,
            )
            for problem in _problems(cookie, https=origin_of_cookie.startswith("https://")):
                by_problem.setdefault((origin_of_cookie, problem.rule_id), []).append(cookie.name)
        for (origin, rule_id), names in by_problem.items():
            problem = problems_by_id[rule_id]
            names = sorted(set(names))
            candidates.append(
                PassiveCandidate(
                    rule_id=problem.rule_id,
                    title=f"{problem.title} ({origin.split('://', 1)[1]}, after login as {label})",
                    severity=_severity(problem, names),
                    cwe=problem.cwe,
                    owasp="A05:2021",
                    origin=origin,
                    subject=f"{label}:{','.join(names)}",
                    narrative=(
                        f"{problem.what} Cookies: {', '.join(names)}, as stored by the browser "
                        f"after logging in as '{label}'. (Seen once during the login; not "
                        "re-checked, so this is reported as probable.)"
                    ),
                    remediation_summary=problem.fix,
                    remediation_steps=problem.steps,
                    reproduction_curl=(
                        f"# Log in as {label} in a browser, then open DevTools > Application > "
                        f"Cookies > {origin} and look at the Secure / HttpOnly / SameSite "
                        f"columns for: {', '.join(names)}"
                    ),
                    reproduction_expect="The flag described above is not ticked for these cookies.",
                    evidence=[],
                    reproduce=None,
                )
            )
    ctx.log(
        "info",
        f"Cookie check: {seen_cookies} cookie(s) examined, {len(candidates)} issue(s) found.",
    )
    return candidates
