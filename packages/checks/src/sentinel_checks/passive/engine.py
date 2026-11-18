"""run_passive_checks: runs every passive check in a fixed order, isolating
failures so that one broken check never costs the others."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .cookies import check_cookies
from .cors import check_cors
from .exposed_files import check_exposed_files
from .headers import check_security_headers
from .models import PassiveCandidate, PassiveContext
from .tls import check_tls

# Order matters: the cookie check reuses the pages the header check fetched.
CHECKS: list[tuple[str, Callable[[PassiveContext], Awaitable[list[PassiveCandidate]]]]] = [
    ("security headers", check_security_headers),
    ("cookies", check_cookies),
    ("CORS", check_cors),
    ("exposed files", check_exposed_files),
    ("TLS", check_tls),
]


@dataclass(slots=True)
class PassiveResult:
    candidates: list[PassiveCandidate] = field(default_factory=list)
    # check name -> number of issues it proposed.
    per_check: dict[str, int] = field(default_factory=dict)
    # check name -> why it could not run.
    failed: dict[str, str] = field(default_factory=dict)
    requests: int = 0


async def run_passive_checks(ctx: PassiveContext) -> PassiveResult:
    result = PassiveResult()
    for name, check in CHECKS:
        try:
            found = await check(ctx)
        except Exception as exc:  # noqa: BLE001 — one broken check must not cost the others
            reason = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
            result.failed[name] = reason
            ctx.log("error", f"The {name} check crashed and was skipped: {reason}")
            continue
        result.per_check[name] = len(found)
        result.candidates.extend(found)
    result.requests = ctx.requests
    return result
