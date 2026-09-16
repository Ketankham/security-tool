"""Scan lifecycle states (docs/01-architecture.md §5).

Two levels, deliberately: ``ScanState`` is the coarse status shown on the
scan as a whole (what the dashboard polls); ``ScanPhaseName``/``PhaseStatus``
track the finer-grained, individually-resumable phases underneath, several
of which run concurrently once ``TESTING`` is entered. A crashed
active-injection phase restarts from its own checkpoint without re-crawling
— that's what having two levels buys us.
"""

from __future__ import annotations

from enum import Enum


class ScanState(str, Enum):
    QUEUED = "queued"
    SCOPE_VERIFYING = "scope_verifying"
    BLOCKED_UNVERIFIED = "blocked_unverified"  # terminal failure
    RECON = "recon"
    AUTH_ESTABLISHING = "auth_establishing"
    FAILED_AUTH = "failed_auth"  # terminal failure
    CRAWLING = "crawling"
    SURFACE_MAPPING = "surface_mapping"
    PASSIVE_CHECKS = "passive_checks"
    TESTING = "testing"  # active_injection + access_control +
    # session_checks + business_logic, parallel
    VERIFYING = "verifying"
    TRIAGING = "triaging"
    REPORTING = "reporting"
    COMPLETE = "complete"  # terminal success
    PAUSED = "paused"
    CANCELLED = "cancelled"  # terminal
    FAILED = "failed"  # terminal


TERMINAL_STATES: frozenset[ScanState] = frozenset(
    {
        ScanState.COMPLETE,
        ScanState.CANCELLED,
        ScanState.FAILED,
        ScanState.BLOCKED_UNVERIFIED,
        ScanState.FAILED_AUTH,
    }
)

# States reachable from PAUSED/CANCELLED/FAILED as a "pause point" or
# "interrupt point" — i.e. everything that isn't already terminal.
INTERRUPTIBLE_STATES: frozenset[ScanState] = frozenset(
    s for s in ScanState if s not in TERMINAL_STATES and s is not ScanState.PAUSED
)


class ScanPhaseName(str, Enum):
    SCOPE_VERIFYING = "scope_verifying"
    RECON = "recon"
    AUTH_ESTABLISHING = "auth_establishing"
    CRAWLING = "crawling"
    SURFACE_MAPPING = "surface_mapping"
    PASSIVE_CHECKS = "passive_checks"
    ACTIVE_INJECTION = "active_injection"
    ACCESS_CONTROL = "access_control"
    SESSION_CHECKS = "session_checks"
    BUSINESS_LOGIC = "business_logic"  # v1.5 — SKIPPED in v1 (docs/05)
    VERIFYING = "verifying"
    TRIAGING = "triaging"
    REPORTING = "reporting"


# The phases that run concurrently once PASSIVE_CHECKS completes.
PARALLEL_TESTING_PHASES: frozenset[ScanPhaseName] = frozenset(
    {
        ScanPhaseName.ACTIVE_INJECTION,
        ScanPhaseName.ACCESS_CONTROL,
        ScanPhaseName.SESSION_CHECKS,
        ScanPhaseName.BUSINESS_LOGIC,
    }
)


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # e.g. business_logic in v1, or a degraded-mode skip
