"""Import every model so Base.metadata is complete for Alembic autogenerate
and so the before_flush invariant in finding.py is always registered."""

from ..base import Base
from .asset import Asset, Endpoint, Parameter
from .finding import Evidence, Finding, Verification
from .organization import Organization, User
from .persona import Credential, Persona
from .report import Report
from .scan import Scan, ScanPhase, ScanPolicy
from .target import ScopeRule, Target
from .transcript import TranscriptRecord

__all__ = [
    "Base",
    "Organization",
    "User",
    "Target",
    "ScopeRule",
    "Persona",
    "Credential",
    "ScanPolicy",
    "Scan",
    "ScanPhase",
    "Asset",
    "Endpoint",
    "Parameter",
    "TranscriptRecord",
    "Finding",
    "Evidence",
    "Verification",
    "Report",
]
