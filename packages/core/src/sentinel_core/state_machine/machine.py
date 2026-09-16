"""ScanStateMachine: the pure transition logic behind every scan (docs/01
§5).

Deliberately persistence-agnostic — packages/db wraps this with a SQLAlchemy
model that reads/writes ``current`` and ``paused_from`` as columns, and every
Celery task calls ``transition()`` before starting a phase so a crashed
worker leaves the scan in a state a retry can resume from, not a state
that silently looks complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .states import TERMINAL_STATES, ScanState

_LINEAR_TRANSITIONS: dict[ScanState, set[ScanState]] = {
    ScanState.QUEUED: {ScanState.SCOPE_VERIFYING},
    ScanState.SCOPE_VERIFYING: {ScanState.RECON, ScanState.BLOCKED_UNVERIFIED},
    ScanState.RECON: {ScanState.AUTH_ESTABLISHING},
    # AUTH_ESTABLISHING can proceed to CRAWLING even on a failed *optional*
    # auth (the scan continues unauthenticated and is marked degraded at the
    # phase level — see ScanPhase.stats_json) or fail hard if auth was
    # required for this target.
    ScanState.AUTH_ESTABLISHING: {ScanState.CRAWLING, ScanState.FAILED_AUTH},
    ScanState.CRAWLING: {ScanState.SURFACE_MAPPING},
    ScanState.SURFACE_MAPPING: {ScanState.PASSIVE_CHECKS},
    ScanState.PASSIVE_CHECKS: {ScanState.TESTING},
    ScanState.TESTING: {ScanState.VERIFYING},
    ScanState.VERIFYING: {ScanState.TRIAGING},
    ScanState.TRIAGING: {ScanState.REPORTING},
    ScanState.REPORTING: {ScanState.COMPLETE},
}


class InvalidTransition(RuntimeError):
    def __init__(self, current: ScanState, target: ScanState) -> None:
        self.current = current
        self.target = target
        super().__init__(f"Cannot transition scan from {current.value!r} to {target.value!r}.")


class InvalidResume(RuntimeError):
    pass


@dataclass
class ScanStateMachine:
    current: ScanState = ScanState.QUEUED
    paused_from: ScanState | None = field(default=None)
    fail_reason: str | None = field(default=None)

    @property
    def is_terminal(self) -> bool:
        return self.current in TERMINAL_STATES

    def can_transition(self, target: ScanState) -> bool:
        if self.is_terminal:
            return False
        if target is ScanState.PAUSED:
            return self.current is not ScanState.PAUSED
        if target in (ScanState.CANCELLED, ScanState.FAILED):
            return True
        return target in _LINEAR_TRANSITIONS.get(self.current, set())

    def transition(self, target: ScanState, *, reason: str | None = None) -> ScanState:
        if not self.can_transition(target):
            raise InvalidTransition(self.current, target)
        if target is ScanState.PAUSED:
            self.paused_from = self.current
        if target is ScanState.FAILED:
            self.fail_reason = reason
        self.current = target
        return self.current

    def resume(self) -> ScanState:
        if self.current is not ScanState.PAUSED:
            raise InvalidResume(
                f"Cannot resume a scan that is not paused (current={self.current.value!r})."
            )
        if self.paused_from is None:
            raise InvalidResume("Paused scan has no recorded pre-pause state to resume into.")
        self.current = self.paused_from
        self.paused_from = None
        return self.current
