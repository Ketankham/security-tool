"""Authorization engine (docs/03-check-catalogue.md §4) — the moat.

Replays each authenticated persona's observed requests as every identity
that should be denied them, judges the result with the layered access
oracle, and gates every positive through the deterministic Verifier before
it can be confirmed.
"""

from .engine import AuthorizationEngine
from .matrix import personas_that_should_be_denied
from .models import (
    AccessVerdict,
    AuthzBoundary,
    AuthzFinding,
    Confidence,
    EvidenceItem,
    ObservedRequest,
    OracleLayer,
    OracleResponse,
    OracleResult,
    PersonaProfile,
    Severity,
)
from .oracle import access_oracle

__all__ = [
    "AuthorizationEngine",
    "personas_that_should_be_denied",
    "access_oracle",
    "AccessVerdict",
    "AuthzBoundary",
    "AuthzFinding",
    "Confidence",
    "EvidenceItem",
    "ObservedRequest",
    "OracleLayer",
    "OracleResponse",
    "OracleResult",
    "PersonaProfile",
    "Severity",
]
