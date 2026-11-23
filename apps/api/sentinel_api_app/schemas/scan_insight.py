from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScanEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    at: datetime
    stage: str
    level: str
    persona: str | None
    message: str
    data: dict


class ScanEventsOut(BaseModel):
    events: list[ScanEventOut]
    # Events in the scan (any filter ignored), so the UI can say "showing X of N".
    total: int
    # The highest seq in `events`; pass it as after_seq to get only newer ones.
    last_seq: int


class ScanEndpointOut(BaseModel):
    host: str
    method: str
    path_template: str
    source: str
    # Persona ids that reached it ("anonymous" is the logged-out visitor).
    persona_ids: list[str]


class ToolRunOut(BaseModel):
    """One tool invocation. Output bodies are fetched separately (they can
    be large); a short preview comes with the list."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    seq: int
    phase: str
    tool: str
    binary: str | None
    version: str | None
    command: str
    status: str
    skip_reason: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    exit_code: int | None
    timed_out: bool
    results_count: int
    stdout_chars: int
    stderr_chars: int
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_preview: str
    stderr_preview: str


class ScanAssetOut(BaseModel):
    host: str
    discovery_source: str
    sources: list[str]
    scope_status: str
    scope_reason: str | None
    ip_addresses: list[str]
    live: bool
    tech: list[str]
    http_probes: list[dict]
    endpoints: int
