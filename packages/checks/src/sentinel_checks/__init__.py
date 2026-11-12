"""Passive/config, injection, authz, session-management and (v1.5)
business-logic checks. Roadmap: M2-M3 (docs/03-check-catalogue.md).

M2 slice 1 (this milestone): the authorization engine's core three
boundaries (vertical/horizontal/anonymous — see ``access_control``) and the
Phase 9 verification gate (``verification``). Passive/config checks,
injection, session-management, the parameter-level IDOR sweep, and Layer 4
LLM adjudication are not implemented yet — see the relevant module
docstrings for what each depends on.
"""

__version__ = "0.1.0"
