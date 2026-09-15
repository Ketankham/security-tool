"""Multi-persona authenticated crawler (docs/02-scan-lifecycle.md Phase 3).

surface = await PersonaCrawler(scope_guard=..., rate_limiter=..., target_id=...).crawl(
    browser, root_url="https://acme.test/", persona_id="admin", storage_state=admin_storage_state
)
"""

from .crawler import PersonaCrawler
from .models import DiscoveredEndpoint, DiscoverySource, SurfaceMap
from .surface_mapper import normalize_path

__all__ = [
    "PersonaCrawler",
    "SurfaceMap",
    "DiscoveredEndpoint",
    "DiscoverySource",
    "normalize_path",
]
