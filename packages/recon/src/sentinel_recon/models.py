"""Recon result types (docs/02-scan-lifecycle.md Phase 1)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    url: str
    status_code: int | None
    title: str | None
    server: str | None
    tech: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    host: str
    source: str  # "root_domain" | "subfinder" | ...
    ips: list[str] = field(default_factory=list)
    http_probes: list[HttpProbeResult] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ReconResult:
    root_domain: str
    assets: list[DiscoveredAsset]
    tool_availability: dict[str, bool]
    wildcard_dns_suspected: bool
    notes: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return not all(self.tool_availability.values())
