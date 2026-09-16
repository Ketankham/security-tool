"""Data types for the authorization engine (docs/03-check-catalogue.md §4,
docs/02-scan-lifecycle.md Phase 6) — the product's moat.

Deliberately plain dataclasses with no sentinel_db/sentinel_crawler
dependency: this package reasons about identities and requests in the
abstract, and apps/worker's adapter module is what translates DB rows and
SurfaceMap objects into these shapes. Same separation as sentinel_auth and
sentinel_crawler.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

ANONYMOUS_PERSONA_ID = "anonymous"

#: The four boundaries from docs/03 §4.1. Object/IDOR is deferred here — it
#: needs AI parameter classification (docs/02 Phase 3 step 5, not yet built)
#: to know which params are object references worth substituting IDs into.
Boundary = str  # "vertical" | "horizontal" | "anonymous"


@dataclass(frozen=True, slots=True)
class PersonaIdentity:
    """The minimal shape the replay matrix needs from a persona — no
    credentials, no session state, just what generates the boundary rules
    (docs/03 §4.1's ``Q.trust_rank`` / ``Q.tenant_key``)."""

    persona_id: str
    trust_rank: int
    tenant_key: str | None
    canary_tokens: tuple[str, ...] = ()


#: The synthetic zero-trust identity every replay matrix includes — not a
#: row anywhere (mirrors sentinel_crawler's always-on anonymous crawl).
ANONYMOUS_IDENTITY = PersonaIdentity(
    persona_id=ANONYMOUS_PERSONA_ID, trust_rank=0, tenant_key=None, canary_tokens=()
)


@dataclass(frozen=True, slots=True)
class ObservedRequest:
    """One concrete request seen during persona P's crawl. Only GET requests
    are replayed this slice — state-changing method-tampering checks
    (docs/03 §4.5) are a follow-up, replaying non-idempotent requests needs
    its own blast-radius discipline (docs/02 Phase 5)."""

    method: str
    url: str
    path_template: str
    requesting_persona_id: str


class OracleVerdict(str, Enum):
    """docs/03 §4.4's layered access oracle, Layers 1-3 (deterministic).
    Layer 4 (LLM semantic adjudication of the ambiguous middle) is not
    implemented yet — an AMBIGUOUS verdict is the honest result of that gap,
    not a bug; it means "layers 1-3 could not clear this endpoint, and
    without an LLM judge or a canary we won't guess," so it does not become
    a candidate. Layer 5 (mandatory re-verification before `confirmed`) is
    ``sentinel_checks.verification``, not this module."""

    NOT_A_FINDING = "not_a_finding"
    CONFIRMED_BY_CANARY = "confirmed_by_canary"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class AccessCandidate:
    """A pre-verification candidate produced by the access-control engine.
    Never persisted directly as a CONFIRMED Finding — sentinel_checks knows
    nothing about the DB; apps/worker's adapter runs this back through
    ``sentinel_checks.verification.verify_candidate`` before writing
    anything (ADR-0001)."""

    rule_id: str  # "authz.vertical" | "authz.horizontal" | "authz.anonymous"
    boundary: Boundary
    requesting_persona_id: str
    denied_persona_id: str
    request: ObservedRequest
    verdict: OracleVerdict
    denied_status_code: int
    detail: str
    denied_transcript_id: str


@dataclass(frozen=True, slots=True)
class AccessControlResult:
    """``candidates`` only ever holds CONFIRMED_BY_CANARY verdicts — an
    AMBIGUOUS diff has nothing adjudicating it yet (no Layer 4), and turning
    an un-adjudicated diff into a customer-facing finding would itself
    violate "AI proposes, deterministic replay disposes": here, nothing
    proposes it at all. ``ambiguous_count`` exists so the caller can report
    that gap honestly (a degraded-mode note) instead of hiding it."""

    candidates: list[AccessCandidate]
    ambiguous_count: int
