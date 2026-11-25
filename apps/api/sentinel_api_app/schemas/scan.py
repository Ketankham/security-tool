from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StringConstraints
from sentinel_core.authorisation import MAX_CLIENT_NAME_CHARS
from sentinel_core.scan_options import (
    DEFAULT_DEPTH,
    DEFAULT_RECON_PROFILE,
    DEFAULT_SPEED,
    DEFAULT_WORDLIST,
    Depth,
    ReconProfile,
    Speed,
    TargetEnvironment,
    Wordlist,
)
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


class AuthorisationIn(BaseModel):
    """The "I'm authorised" confirmation that active tools need (see
    sentinel_core.authorisation). ``statement_version`` is the version the
    person was shown; a stale one is refused so a stored record always matches
    wording that was really on screen.

    ``client_name`` is stripped and capped here; an empty name is rejected by
    the scan routes (with the same message as a missing confirmation) rather
    than by schema validation, so the person sees one clear instruction."""

    accepted: bool
    client_name: Annotated[
        str, StringConstraints(strip_whitespace=True, max_length=MAX_CLIENT_NAME_CHARS)
    ]
    statement_version: str
    all_ports_confirmed: bool = False


class ScanCreate(BaseModel):
    triggered_by: str = "manual"
    # See sentinel_core.scan_options: requests/second and pages per persona.
    speed: Speed = DEFAULT_SPEED
    depth: Depth = DEFAULT_DEPTH
    recon_profile: ReconProfile = DEFAULT_RECON_PROFILE
    # Active tools (off by default): see sentinel_core.scan_options.
    dir_bruteforce: bool = False
    port_scan: bool = False
    all_ports: bool = False
    wordlist: Wordlist = DEFAULT_WORDLIST
    # None means "from the target": production when Target.is_production, else staging.
    target_environment: TargetEnvironment | None = None
    authorisation: AuthorisationIn | None = None


class ScanRetry(BaseModel):
    """Optional body of POST /scans/{id}/retry. Needed only when the scan being
    retried used active tools: either confirm again (``authorisation``) or
    retry without them (``drop_active_tools``)."""

    authorisation: AuthorisationIn | None = None
    drop_active_tools: bool = False


class ScanAuthorisationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    target_id: UUID
    username: str
    accepted_at: datetime
    statement_version: str
    statement_text: str
    client_name: str
    target_name: str
    tools: list[str]
    all_ports_confirmed: bool
    target_environment: str
    options_snapshot: dict
    client_ip: str | None
    user_agent: str | None
    carried_over_from_scan_id: UUID | None
    created_at: datetime
    updated_at: datetime


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_id: UUID
    state: ScanState
    triggered_by: str
    is_degraded: bool
    degraded_reasons: list[str]
    fail_reason: str | None
    requested_by: str | None = None
    options: dict = {}
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    llm_tokens_used: int
    llm_token_budget: int
    phases: list[ScanPhaseOut] = []
