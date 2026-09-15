"""Persona sessions: AI-assisted LoginRecipe recording (M2) + deterministic
replay (this milestone), session oracle (docs/01 §6.5), and the
PersonaSession bridge into sentinel_core.http_engine.
"""

from .browser import chromium_launch_kwargs
from .models import Credential, LoginRecipe, LoginReplayResult, LoginStep, SuccessAssertion
from .oracle import OracleEstablishmentResult, SessionOracle, establish_session_oracle
from .persona_session import PersonaSession
from .replay import LoginReplayer, new_browser

__all__ = [
    "LoginRecipe",
    "LoginStep",
    "SuccessAssertion",
    "LoginReplayResult",
    "Credential",
    "LoginReplayer",
    "new_browser",
    "PersonaSession",
    "SessionOracle",
    "OracleEstablishmentResult",
    "establish_session_oracle",
    "chromium_launch_kwargs",
]
