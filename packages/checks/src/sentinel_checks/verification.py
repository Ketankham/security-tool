"""Phase 9 — the non-negotiable verification gate (docs/02-scan-lifecycle.md
Phase 9, ADR-0001): every candidate, whatever check produced it, is
independently re-executed from scratch at least twice before it can be
labelled ``confirmed``. Purely deterministic, no AI — this is the "replay
disposes" half of the split, and it's deliberately check-agnostic (a
``reproduce`` thunk) so M3's injection/session checks reuse this same gate
instead of each check reimplementing its own reproduction-counting.

``sentinel_db.models.finding.MIN_REPRODUCTIONS_FOR_CONFIRMED`` is the
authoritative constant this mirrors; this package can't depend on
sentinel_db (no check package does), so the two are kept in sync by a
cross-check test in apps/worker rather than a shared import.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

MIN_REPRODUCTIONS_FOR_CONFIRMED = 2


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    attempted_count: int
    reproduced_count: int

    @property
    def passed(self) -> bool:
        return self.reproduced_count >= MIN_REPRODUCTIONS_FOR_CONFIRMED


async def verify_candidate(
    reproduce: Callable[[], Awaitable[bool]], *, attempts: int = MIN_REPRODUCTIONS_FOR_CONFIRMED
) -> VerificationOutcome:
    """Calls ``reproduce`` ``attempts`` times, independently — no caching,
    no short-circuiting on an early failure, since a flaky reproduction
    *is* the signal (docs/02 Phase 9: "Non-reproducing candidates are
    demoted to probable ... or dropped")."""
    reproduced = 0
    for _ in range(attempts):
        if await reproduce():
            reproduced += 1
    return VerificationOutcome(attempted_count=attempts, reproduced_count=reproduced)
