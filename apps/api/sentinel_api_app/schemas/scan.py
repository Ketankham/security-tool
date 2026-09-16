from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState


class ScanPolicyCreate(BaseModel):
    intensity: str = "standard"
    read_write_enabled: bool = False
    max_requests_per_second: float = 5.0
    schedule_cron: str | None = None


class ScanPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    intensity: str
    read_write_enabled: bool
    max_requests_per_second: float
    schedule_cron: str | None


class ScanPhaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: ScanPhaseName
    status: PhaseStatus
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    stats_json: dict


class ScanCreate(BaseModel):
    triggered_by: str = "manual"


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_id: UUID
    state: ScanState
    triggered_by: str
    is_degraded: bool
    degraded_reasons: list[str]
    fail_reason: str | None
    started_at: datetime | None
    finished_at: datetime | None
    llm_tokens_used: int
    llm_token_budget: int
    phases: list[ScanPhaseOut] = []
