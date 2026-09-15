"""Destructive-action guard (docs/04-edge-cases.md §A1).

A crawler that clicks every link will eventually click "Delete account" or
fire a DELETE on a real record. This guard is consulted by the crawler
*before* any interaction (click, form submit, non-GET request) and by the
active-injection phase before any mutating payload. It is deliberately
conservative: default-deny on ambiguity, because the cost of a missed click
is a customer's data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Matched case-insensitively against the URL path, query, and any visible
# link/button text the caller supplies.
DEFAULT_DESTRUCTIVE_PATTERNS: tuple[str, ...] = (
    r"\bdelete\b",
    r"\bdeletes?\b",
    r"\bremove\b",
    r"\bdeactivat\w*\b",
    r"\bcancel\b",
    r"\bunsubscrib\w*\b",
    r"\bpurge\b",
    r"\breset\b",
    r"\bdestroy\b",
    r"\bterminat\w*\b",
    r"\bclose[-_ ]?account\b",
    r"\blogout\b",
    r"\bsign[-_ ]?out\b",
    r"\brevoke\b",
    r"\bwipe\b",
    r"\bdrop\b",
    r"\btruncat\w*\b",
    r"\bforget[-_ ]?me\b",
)

# Non-idempotent methods are treated as suspect by default (docs/04 A1) even
# without a matching text pattern, unless the caller has explicitly marked
# the scan policy as read-write for this target.
NON_IDEMPOTENT_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class DestructiveCheck:
    is_suspect: bool
    reason: str
    matched_pattern: str | None = None


@dataclass(slots=True)
class DestructiveActionGuard:
    read_write_enabled: bool = False
    extra_patterns: tuple[str, ...] = field(default_factory=tuple)
    _compiled: list[re.Pattern[str]] = field(default_factory=list, repr=False, init=False)

    def __post_init__(self) -> None:
        patterns = DEFAULT_DESTRUCTIVE_PATTERNS + tuple(self.extra_patterns)
        self._compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    def check(self, *, method: str, url: str, link_text: str = "") -> DestructiveCheck:
        method = method.upper()
        parts = urlsplit(url)
        haystack = " ".join([parts.path, parts.query, link_text])

        for pattern in self._compiled:
            if pattern.search(haystack):
                return DestructiveCheck(
                    is_suspect=True,
                    reason=f"URL/label matches destructive-action pattern '{pattern.pattern}'.",
                    matched_pattern=pattern.pattern,
                )

        if method in NON_IDEMPOTENT_METHODS and not self.read_write_enabled:
            return DestructiveCheck(
                is_suspect=True,
                reason=(
                    f"Method {method} is non-idempotent and this target's scan "
                    "policy has not opted into read-write testing (default: read-only)."
                ),
            )

        return DestructiveCheck(is_suspect=False, reason="No destructive signal detected.")
