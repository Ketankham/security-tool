"""Verifier: the check-agnostic re-proof gate (docs/02 Phase 9, ADR-0001).

It knows nothing about authorization, injection, or any specific check. A
caller hands it a ``reproduce`` coroutine that performs *one* fresh,
independent attempt to trigger the candidate and reports whether it
reproduced. The Verifier runs it ``attempts`` times and decides ``passed``.

    outcome = await Verifier().verify(reproduce)
    if outcome.passed:
        finding.confidence = CONFIRMED   # and only then

Strictness is deliberate (docs/00: near-zero false positives is the whole
product): ``passed`` requires EVERY attempt to reproduce, not a majority. A
candidate that reproduces 1-of-2 is flaky, and a flaky authorization verdict
is exactly the kind of false positive we refuse to ship as confirmed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import structlog

from .models import MIN_REPRODUCTIONS, ReproductionAttempt, VerificationOutcome

log = structlog.get_logger(__name__)

# A single attempt coroutine. Receives the 0-based attempt index (useful for
# logging / staggering) and returns whether this attempt reproduced.
Reproducer = Callable[[int], Awaitable[ReproductionAttempt]]


class Verifier:
    def __init__(self, *, min_reproductions: int = MIN_REPRODUCTIONS) -> None:
        if min_reproductions < 1:
            raise ValueError("min_reproductions must be >= 1")
        self._min = min_reproductions

    async def verify(
        self, reproduce: Reproducer, *, attempts: int | None = None
    ) -> VerificationOutcome:
        """Run ``reproduce`` ``attempts`` times (default: ``min_reproductions``)
        and return the outcome. Stops early the first time an attempt fails to
        reproduce — one non-reproduction already means it can't pass, and
        re-running a target more than necessary is a courtesy we extend by
        default (docs/06 blast-radius discipline)."""
        n = attempts if attempts is not None else self._min
        if n < self._min:
            raise ValueError(
                f"attempts ({n}) must be >= min_reproductions ({self._min}) — "
                "a run that can't possibly satisfy the confirmed bar is a bug, not a request."
            )

        results: list[ReproductionAttempt] = []
        reproduced_count = 0
        for i in range(n):
            attempt = await reproduce(i)
            results.append(attempt)
            if attempt.reproduced:
                reproduced_count += 1
            else:
                # Early-out: a single miss already fails the all-must-reproduce
                # bar, so there's no reason to keep hitting the target.
                log.info(
                    "verifier.not_reproduced",
                    attempt=i,
                    detail=attempt.detail,
                    attempts_run=i + 1,
                )
                break

        passed = reproduced_count == n and reproduced_count >= self._min
        return VerificationOutcome(
            attempted_count=len(results),
            reproduced_count=reproduced_count,
            passed=passed,
            attempts=tuple(results),
        )
