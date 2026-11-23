"""What the Run scan choices mean. Shared by the API (validation, display)
and the worker (enforcement), so both agree.

speed: requests per second to the target, for every request the scan makes
    (crawler and HTTP engine share one rate limiter per target). "gentle" is
    for small or fragile client sites; the limiter also backs off on its own
    when the site answers 429/503.
depth: how many pages each persona's crawl may visit.
recon_profile: how far recon goes. "light" (default, safe for client
    production) uses subfinder's default data sources and checks up to 50
    hosts. "full" asks every subfinder data source (slower, finds more) and
    checks up to 150 hosts. Deeper tools (ports, directories) will key off
    this too; each of those also needs its own explicit authorisation.
"""

from __future__ import annotations

from typing import Literal

Speed = Literal["gentle", "normal", "fast"]
Depth = Literal["quick", "standard", "deep"]
ReconProfile = Literal["light", "full"]

REQUESTS_PER_SECOND: dict[str, float] = {"gentle": 2.0, "normal": 5.0, "fast": 10.0}
MAX_PAGES_PER_PERSONA: dict[str, int] = {"quick": 30, "standard": 100, "deep": 300}

DEFAULT_SPEED: Speed = "normal"
DEFAULT_DEPTH: Depth = "standard"
DEFAULT_RECON_PROFILE: ReconProfile = "light"
RECON_PROFILES: tuple[str, ...] = ("light", "full")


def resolve(options: dict | None) -> tuple[float, int]:
    """(requests per second, max pages per persona) for a scan's stored
    options; unknown or missing values fall back to the defaults."""
    options = options or {}
    rps = REQUESTS_PER_SECOND.get(str(options.get("speed")), REQUESTS_PER_SECOND[DEFAULT_SPEED])
    pages = MAX_PAGES_PER_PERSONA.get(
        str(options.get("depth")), MAX_PAGES_PER_PERSONA[DEFAULT_DEPTH]
    )
    return rps, pages


def resolve_recon_profile(options: dict | None) -> ReconProfile:
    """The scan's recon profile; scans created before profiles existed (and
    any unknown value) get the safe default, light."""
    value = str((options or {}).get("recon_profile"))
    return "full" if value == "full" else DEFAULT_RECON_PROFILE
