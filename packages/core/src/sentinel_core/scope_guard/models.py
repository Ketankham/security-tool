"""Scope rule and decision types.

A Target's scope is the legal and technical boundary of what this scan is
allowed to touch (docs/06-safety-legal-abuse.md §2). Every outbound request
in the system is checked against it before it leaves — see
``core.http_engine.engine.HttpEngine``, the single choke point that consults
this guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

RuleKind = Literal["host", "path_prefix", "path_regex", "method"]
RuleEffect = Literal["include", "exclude"]


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """One include/exclude rule. Exclude rules always win over include rules
    of the same or broader kind (see ScopeGuard.evaluate)."""

    kind: RuleKind
    pattern: str
    effect: RuleEffect
    label: str = ""


class ScopeVerdict(str, Enum):
    ALLOWED = "allowed"
    BLOCKED_HOST = "blocked_host"
    BLOCKED_PATH_EXCLUDED = "blocked_path_excluded"
    BLOCKED_PATH_NOT_INCLUDED = "blocked_path_not_included"
    BLOCKED_METHOD = "blocked_method"
    BLOCKED_UNVERIFIED_TARGET = "blocked_unverified_target"


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    verdict: ScopeVerdict
    reason: str
    matched_rule: ScopeRule | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict is ScopeVerdict.ALLOWED
