from __future__ import annotations

from sentinel_core.scope_guard import ScopeDecision


class ScopeViolation(RuntimeError):
    """Raised when a request is blocked by the ScopeGuard. Callers must not
    catch this and silently retry out of scope — see docs/06 §2."""

    def __init__(self, decision: ScopeDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason)
