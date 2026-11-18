"""Recon result types (docs/02-scan-lifecycle.md Phase 1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Why a host was or wasn't probed. The tester asked to see this per host,
# not just the hosts that worked.
SCOPE_IN = "in_scope"
SCOPE_EXCLUDED = "excluded"  # a scope rule blocks it
SCOPE_PRIVATE_IP = "private_ip"  # resolves to a non-public address
SCOPE_UNRESOLVED = "unresolved"  # no DNS A record
SCOPE_CAPPED = "capped"  # over the per-scan host budget


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    url: str
    status_code: int | None
    title: str | None
    server: str | None
    tech: list[str] = field(default_factory=list)
    error: str | None = None
    host: str | None = None  # the input host this probe was for
    cdn: str | None = None  # CDN/WAF name if httpx recognised one
    content_type: str | None = None


@dataclass(frozen=True, slots=True)
class ToolRun:
    """One external (or built-in) tool invocation, kept so a tester can see
    exactly what ran, with what arguments, and what it printed."""

    tool: str  # "subfinder" | "httpx" | "dns" | "http-probe (built-in)"
    status: str  # ok | failed | timed_out | not_installed | skipped
    command: str = ""  # the command line as run (or a description for built-ins)
    binary: str | None = None
    version: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    results_count: int = 0
    skip_reason: str | None = None

    @property
    def duration_ms(self) -> int | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return int((self.finished_at - self.started_at).total_seconds() * 1000)


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    host: str
    source: str  # first source: "root_domain" | "subfinder" | ...
    ips: list[str] = field(default_factory=list)
    http_probes: list[HttpProbeResult] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # e.g. ["crtsh", "alienvault"]
    scope_status: str = SCOPE_IN
    scope_reason: str | None = None

    @property
    def live(self) -> bool:
        return any(p.status_code is not None for p in self.http_probes)

    @property
    def tech(self) -> list[str]:
        seen: dict[str, None] = {}
        for probe in self.http_probes:
            for name in probe.tech:
                seen.setdefault(name, None)
            if probe.server:
                seen.setdefault(probe.server, None)
        return list(seen)


@dataclass(frozen=True, slots=True)
class ReconResult:
    root_domain: str
    assets: list[DiscoveredAsset]
    tool_availability: dict[str, bool]
    wildcard_dns_suspected: bool
    notes: list[str] = field(default_factory=list)
    tool_runs: list[ToolRun] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return not all(self.tool_availability.values())

    @property
    def live_assets(self) -> list[DiscoveredAsset]:
        return [a for a in self.assets if a.scope_status == SCOPE_IN and a.live]
