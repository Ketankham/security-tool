"""What the Run scan choices mean. Shared by the API (validation, display)
and the worker (enforcement), so both agree.

speed: requests per second to the target, for every request the scan makes
    (crawler and HTTP engine share one rate limiter per target). "gentle" is
    for small or fragile client sites; the limiter also backs off on its own
    when the site answers 429/503.
depth: how many pages each persona's crawl may visit.
"""

from __future__ import annotations

from typing import Literal

Speed = Literal["gentle", "normal", "fast"]
Depth = Literal["quick", "standard", "deep"]

REQUESTS_PER_SECOND: dict[str, float] = {"gentle": 2.0, "normal": 5.0, "fast": 10.0}
MAX_PAGES_PER_PERSONA: dict[str, int] = {"quick": 30, "standard": 100, "deep": 300}

DEFAULT_SPEED: Speed = "normal"
DEFAULT_DEPTH: Depth = "standard"


def resolve(options: dict | None) -> tuple[float, int]:
    """(requests per second, max pages per persona) for a scan's stored
    options; unknown or missing values fall back to the defaults."""
    options = options or {}
    rps = REQUESTS_PER_SECOND.get(str(options.get("speed")), REQUESTS_PER_SECOND[DEFAULT_SPEED])
    pages = MAX_PAGES_PER_PERSONA.get(
        str(options.get("depth")), MAX_PAGES_PER_PERSONA[DEFAULT_DEPTH]
    )
    return rps, pages
