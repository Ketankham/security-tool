"""Minimal session-state contract the HTTP engine needs from a persona.

Deliberately decoupled from packages/auth's full Persona model (which owns
LoginRecipe replay, TOTP, etc.) so sentinel_core has no dependency on it —
core is the substrate everything else builds on, never the reverse.
"""

from __future__ import annotations

from typing import Protocol


class SessionState(Protocol):
    persona_id: str

    def cookies(self) -> dict[str, str]: ...
    def extra_headers(self) -> dict[str, str]: ...


class AnonymousSession:
    """The always-available zero persona: no cookies, no auth headers.
    Every authz replay matrix includes this as the trust_rank=0 baseline."""

    persona_id = "anonymous"

    def cookies(self) -> dict[str, str]:
        return {}

    def extra_headers(self) -> dict[str, str]:
        return {}
