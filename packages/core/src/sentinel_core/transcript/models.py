"""Transcript data model.

A Transcript is the atomic unit of evidence: one HTTP request/response pair,
scrubbed of secrets, content-addressed, and immutable. Findings reference
transcript IDs (see docs/01-architecture.md §6.6) rather than embedding
bodies, which keeps Postgres small and evidence auditable independent of the
database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None = None


@dataclass(frozen=True, slots=True)
class RecordedResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes | None = None
    elapsed_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class Transcript:
    scan_id: str
    persona_id: str | None
    request: RecordedRequest
    response: RecordedResponse | None  # None if the request errored/timed out
    error: str | None = None
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    transcript_id: str = ""  # filled in by the recorder once content-addressed
