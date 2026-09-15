"""Surface map data types (docs/02-scan-lifecycle.md Phase 3).

The whole point of crawling per-persona rather than once is the diff this
enables later (docs/00 §3 step 4): endpoints reached by an admin persona
but never by a member persona are the first, cheapest signal of a
privilege boundary. `DiscoveredEndpoint.persona_id` is what makes that diff
a query instead of a re-crawl.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

DiscoverySource = Literal["link", "form", "network"]


@dataclass(frozen=True, slots=True)
class DiscoveredEndpoint:
    method: str
    url: str
    path_template: str
    source: DiscoverySource
    persona_id: str


@dataclass(slots=True)
class SurfaceMap:
    """Not frozen, unlike DiscoveredEndpoint: the crawler builds this up
    incrementally over the whole crawl (appending endpoints/notes, then
    setting pages_visited once at the end) rather than constructing it
    complete in one call."""

    root_url: str
    persona_id: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    pages_visited: int = 0
    notes: list[str] = field(default_factory=list)
