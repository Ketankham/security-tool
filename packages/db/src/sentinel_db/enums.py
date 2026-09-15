"""Domain enums that live at the database layer (as opposed to
sentinel_core.state_machine's scan-lifecycle enums, which the substrate
itself depends on and which live in sentinel_core to avoid a dependency
inversion)."""

from __future__ import annotations

import enum


class OrgRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class OwnershipVerificationMethod(str, enum.Enum):
    DNS_TXT = "dns_txt"
    WELL_KNOWN_FILE = "well_known_file"
    META_TAG = "meta_tag"


class LoginStrategy(str, enum.Enum):
    FORM = "form"
    OAUTH_REDIRECT = "oauth_redirect"
    SAML = "saml"
    API_TOKEN = "api_token"
    HAR_REPLAY = "har_replay"
    MANUAL_SESSION = "manual_session"


class CredentialKind(str, enum.Enum):
    PASSWORD = "password"
    TOTP_SECRET = "totp_secret"
    API_TOKEN = "api_token"
    SESSION_IMPORT = "session_import"


class ScanIntensity(str, enum.Enum):
    LIGHT = "light"  # passive + recon only
    STANDARD = "standard"  # + injection + authz + session, read-only
    THOROUGH = "thorough"  # + read-write testing (explicit opt-in target)


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, enum.Enum):
    CONFIRMED = "confirmed"  # requires a passing Verification (enforced, see models/finding.py)
    PROBABLE = "probable"
    INFORMATIONAL = "informational"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    FIXED = "fixed"
    REGRESSED = "regressed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class ReportFormat(str, enum.Enum):
    DASHBOARD = "dashboard"
    PDF = "pdf"
    SARIF = "sarif"
    ATTESTATION_LETTER = "attestation_letter"
