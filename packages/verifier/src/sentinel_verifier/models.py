"""Types for the deterministic re-proof gate (docs/02-scan-lifecycle.md
Phase 9, ADR-0001).

A candidate finding — however it was first proposed (a deterministic oracle,
or, later, an LLM adjudicator) — is only allowed to become
``confidence=CONFIRMED`` once it has been independently re-executed and
reproduced the same positive verdict at least ``MIN_REPRODUCTIONS`` times.
These types are the shape of that re-execution's result.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Mirrors sentinel_db.models.finding.MIN_REPRODUCTIONS_FOR_CONFIRMED. Kept as
# a local constant rather than imported so sentinel-verifier depends only on
# sentinel-core (not sentinel-db) — the DB enforces the same number
# independently, so the two agreeing is a belt-and-braces check, not a
# single point of truth that could drift silently.
MIN_REPRODUCTIONS = 2


@dataclass(frozen=True, slots=True)
class ReproductionAttempt:
    """One independent re-execution of a candidate. ``reproduced`` is the
    only thing that decides the verdict; ``detail``/``observed`` are carried
    through to the finding's evidence so a human can see *why* each attempt
    did or didn't reproduce."""

    reproduced: bool
    detail: str = ""
    observed: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    attempted_count: int
    reproduced_count: int
    passed: bool
    attempts: tuple[ReproductionAttempt, ...] = ()

    @property
    def details(self) -> dict:
        """Serialisable summary for Verification.details / finding evidence."""
        return {
            "attempted_count": self.attempted_count,
            "reproduced_count": self.reproduced_count,
            "passed": self.passed,
            "attempts": [
                {"reproduced": a.reproduced, "detail": a.detail, "observed": a.observed}
                for a in self.attempts
            ],
        }
