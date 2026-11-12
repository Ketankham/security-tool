from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field
from sentinel_core.state_machine import ScanState


class QuickScanCreate(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2000,
        description="A URL or bare domain to scan, e.g. https://example.com or example.com.",
    )


class QuickScanOut(BaseModel):
    scan_id: UUID
    org_id: UUID
    target_id: UUID
    root_domain: str
    state: ScanState
