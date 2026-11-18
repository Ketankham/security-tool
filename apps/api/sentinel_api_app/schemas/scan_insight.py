from __future__ import annotations

from datetime import datetime

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
