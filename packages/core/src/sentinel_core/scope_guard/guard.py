"""ScopeGuard: the pre-flight check every outbound request must pass.

Design principle (docs/01-architecture.md §4.1, docs/06-safety-legal-abuse.md §2):
out-of-scope requests are *blocked*, not merely deprioritised. This module has
no network access and no side effects — it's a pure function of
(allowed hosts, rules, target-verified?) over a candidate request, which
makes it trivial to unit test exhaustively (see packages/core/tests).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .models import ScopeDecision, ScopeRule, ScopeVerdict


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


class ScopeGuard:
    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        rules: list[ScopeRule] | None = None,
        target_ownership_verified: bool,
        default_allowed_methods: set[str] | None = None,
    ) -> None:
        """
        allowed_hosts: hosts (may include ``*.sub.domain`` wildcards) the
            target's ownership verification actually covers. This is the
            hard legal boundary — rules below can narrow it further but
            never widen past it.
        target_ownership_verified: if False, every request is blocked
            regardless of rules (docs/06 §1 — no scan without verification).
        """
        self.allowed_hosts = allowed_hosts
        self.rules = rules or []
        self.target_ownership_verified = target_ownership_verified
        self.default_allowed_methods = default_allowed_methods or {
            "GET",
            "HEAD",
            "OPTIONS",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }

    def evaluate(self, *, method: str, url: str) -> ScopeDecision:
        if not self.target_ownership_verified:
            return ScopeDecision(
                ScopeVerdict.BLOCKED_UNVERIFIED_TARGET,
                "Target ownership has not been verified; no request may be sent. "
                "See docs/06-safety-legal-abuse.md §1.",
            )

        parts = urlsplit(url)
        host = parts.hostname or ""
        path = parts.path or "/"
        method = method.upper()

        if not any(_host_matches(host, h) for h in self.allowed_hosts):
            return ScopeDecision(
                ScopeVerdict.BLOCKED_HOST,
                f"Host '{host}' is not in the verified scope for this target.",
            )

        path_excludes = [
            r
            for r in self.rules
            if r.kind in ("path_prefix", "path_regex") and r.effect == "exclude"
        ]
        for rule in path_excludes:
            if self._path_rule_matches(rule, path):
                return ScopeDecision(
                    ScopeVerdict.BLOCKED_PATH_EXCLUDED,
                    f"Path '{path}' matches exclude rule '{rule.label or rule.pattern}'.",
                    rule,
                )

        path_includes = [
            r
            for r in self.rules
            if r.kind in ("path_prefix", "path_regex") and r.effect == "include"
        ]
        if path_includes and not any(self._path_rule_matches(r, path) for r in path_includes):
            return ScopeDecision(
                ScopeVerdict.BLOCKED_PATH_NOT_INCLUDED,
                f"Path '{path}' does not match any configured include rule, and "
                "include rules are present (allow-listing mode).",
            )

        method_excludes = [r for r in self.rules if r.kind == "method" and r.effect == "exclude"]
        for rule in method_excludes:
            if method == rule.pattern.upper():
                return ScopeDecision(
                    ScopeVerdict.BLOCKED_METHOD,
                    f"Method '{method}' is explicitly excluded ('{rule.label or rule.pattern}').",
                    rule,
                )

        method_includes = {
            r.pattern.upper() for r in self.rules if r.kind == "method" and r.effect == "include"
        }
        allowed_methods = method_includes or self.default_allowed_methods
        if method not in allowed_methods:
            return ScopeDecision(
                ScopeVerdict.BLOCKED_METHOD,
                f"Method '{method}' is not in the allowed method set {sorted(allowed_methods)}.",
            )

        return ScopeDecision(ScopeVerdict.ALLOWED, "In scope.")

    @staticmethod
    def _path_rule_matches(rule: ScopeRule, path: str) -> bool:
        if rule.kind == "path_prefix":
            return path.startswith(rule.pattern)
        if rule.kind == "path_regex":
            return re.search(rule.pattern, path) is not None
        return False
