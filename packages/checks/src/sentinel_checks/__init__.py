"""Check engines (docs/03-check-catalogue.md): passive/config, injection,
authorization, session-management and (v1.5) business-logic.

The authorization engine (``sentinel_checks.authz``) — the product's moat —
is the first to land. The remaining engines follow on M2-M3.
"""

from . import authz

__version__ = "0.1.0"

__all__ = ["authz"]
