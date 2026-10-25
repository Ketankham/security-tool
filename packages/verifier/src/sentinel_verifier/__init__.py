"""Deterministic re-proof gate: every candidate finding is independently
re-executed >=2x before confidence=confirmed (docs/02 Phase 9, ADR-0001).

The Verifier is check-agnostic — it runs a caller-supplied ``reproduce``
coroutine N times and decides ``passed``. The authorization engine
(sentinel_checks) is its first caller; injection/session checks reuse the
same gate.
"""

from .models import MIN_REPRODUCTIONS, ReproductionAttempt, VerificationOutcome
from .verifier import Reproducer, Verifier

__version__ = "0.1.0"

__all__ = [
    "MIN_REPRODUCTIONS",
    "ReproductionAttempt",
    "VerificationOutcome",
    "Reproducer",
    "Verifier",
]
