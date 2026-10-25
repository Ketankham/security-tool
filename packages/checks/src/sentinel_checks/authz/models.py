"""Authorization-engine domain types (docs/03-check-catalogue.md §4).

Deliberately decoupled from the ORM (sentinel_db): the engine works on these
plain dataclasses so it can be unit-tested with no database and no network,
and the worker is responsible for adapting Persona/Endpoint rows into them
and AuthzFinding back into Finding/Evidence/Verification rows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AuthzBoundary(str, Enum):
    """The access-control boundaries we test (docs/03 §4.1). Object/IDOR is
    a planned extension on top of the same replay machinery; the three here
    are what the replay matrix proves directly from persona metadata."""

    VERTICAL = "vertical"  # lower role reaching a higher role's action
    HORIZONTAL = "horizontal"  # one tenant reaching another tenant's data
    ANONYMOUS = "anonymous"  # logged-out reaching authenticated surface


class AccessVerdict(str, Enum):
    DENIED = "denied"  # Q was correctly refused — NOT a finding
    UNAUTHORIZED_ACCESS = "unauthorized_access"  # Q reached what it shouldn't
    INCONCLUSIVE = "inconclusive"  # couldn't establish a baseline to judge against


class OracleLayer(str, Enum):
    """Which layer of the access oracle produced the verdict (docs/03 §4.4).
    Only CANARY is a hard, deterministic proof of data exposure; STATUS and
    STRUCTURE are negative filters; SEMANTIC is the ambiguous middle that
    caps a finding at ``probable``."""

    STATUS = "status"
    STRUCTURE = "structure"
    CANARY = "canary"
    SEMANTIC = "semantic"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class PersonaProfile:
    """The engine's view of one identity. ``anonymous()`` is the always-present
    trust_rank-0 baseline every matrix includes (docs/03 §4.1)."""

    id: str
    label: str
    role_name: str
    trust_rank: int
    tenant_key: str | None = None
    canary_tokens: tuple[str, ...] = ()
    expected_denied: tuple[str, ...] = ()

    @property
    def is_anonymous(self) -> bool:
        return self.trust_rank == 0

    @classmethod
    def anonymous(cls) -> PersonaProfile:
        return cls(id="anonymous", label="Anonymous", role_name="anonymous", trust_rank=0)


@dataclass(frozen=True, slots=True)
class ObservedRequest:
    """A request a persona actually made during its own crawl — the raw
    material of the replay matrix (docs/03 §4.2). ``path_template`` is the
    normalised form (``/users/{id}``) used for finding fingerprints."""

    persona_id: str
    method: str
    url: str
    path_template: str
    body: bytes | None = None


@dataclass(frozen=True, slots=True)
class OracleResponse:
    """The slice of an HTTP response the oracle reasons over. Decoupling it
    from the engine's EngineResponse keeps the oracle a pure function."""

    status_code: int
    text: str

    @property
    def body_len(self) -> int:
        return len(self.text)


@dataclass(frozen=True, slots=True)
class OracleResult:
    verdict: AccessVerdict
    layer: OracleLayer
    reason: str
    # Set only on a CANARY hit: the actor's token that leaked into the
    # subject's response. This is the deterministic proof.
    canary_hit: str | None = None

    @property
    def deterministic(self) -> bool:
        """True when the verdict rests on a hard signal (status/structure/
        canary) rather than an ambiguous judgement. Only a deterministic
        UNAUTHORIZED_ACCESS can ever reach confidence=CONFIRMED."""
        return self.layer is not OracleLayer.SEMANTIC

    @property
    def is_finding(self) -> bool:
        return self.verdict is AccessVerdict.UNAUTHORIZED_ACCESS


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    transcript_id: str
    role: str  # "request-as-admin" | "replay-as-viewer" | ...
    note: str = ""


@dataclass(frozen=True, slots=True)
class AuthzFinding:
    """Engine output. The worker maps this to a Finding (+ Evidence +
    Verification) row; confidence=CONFIRMED is only produced here when a
    deterministic oracle hit was independently reproduced by the Verifier,
    which is also re-checked by the DB's before_flush invariant."""

    rule_id: str
    boundary: AuthzBoundary
    title: str
    severity: Severity
    confidence: Confidence
    actor_persona_id: str
    subject_persona_id: str
    method: str
    url: str
    path_template: str
    oracle: OracleResult
    evidence: tuple[EvidenceItem, ...] = ()
    reproduction: dict = field(default_factory=dict)
    verification: dict = field(default_factory=dict)  # VerificationOutcome.details

    def fingerprint_parts(self) -> tuple[str, str, str, str]:
        """(rule_id, endpoint_template, param, persona_pair) — matches
        sentinel_db Finding.compute_fingerprint so dedup/regression is a
        lookup across scans (docs/01 §6.6)."""
        persona_pair = f"{self.actor_persona_id}->{self.subject_persona_id}"
        return (self.rule_id, self.path_template, self.method, persona_pair)
