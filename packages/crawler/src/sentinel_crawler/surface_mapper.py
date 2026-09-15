"""Path template normalisation (docs/02-scan-lifecycle.md Phase 3 step 4):
collapses `/users/123` and `/users/456` into `/users/{id}` so the surface
map counts one endpoint, not one per object instance. This is also the
basis the IDOR sweep (docs/03 §4.3) builds on — an endpoint template plus
the concrete IDs seen under it.
"""

from __future__ import annotations

import re

_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# A long hex/alphanumeric token (session IDs, Mongo ObjectIds, hashed slugs)
# that isn't plausibly a real path keyword.
_OPAQUE_TOKEN = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_path(path: str) -> str:
    segments = path.split("/")
    normalized = [_normalize_segment(seg) for seg in segments]
    return "/".join(normalized)


def _normalize_segment(segment: str) -> str:
    if (
        _NUMERIC_SEGMENT.match(segment)
        or _UUID_SEGMENT.match(segment)
        or _OPAQUE_TOKEN.match(segment)
    ):
        return "{id}"
    return segment
