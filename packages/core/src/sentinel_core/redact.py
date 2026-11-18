"""Redaction for text that humans will read: the scan activity log.

Complements ``sentinel_core.transcript.scrub`` (which scrubs stored HTTP
transcripts). The log is built from URLs, error messages and page titles,
so the risks are tokens in query strings, bearer/JWT-looking strings, and
any secret value the scan itself holds (a persona's session cookie).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "«redacted»"

# Query parameters whose values are credentials or one-time codes.
_SENSITIVE_PARAM = re.compile(
    r"(?i)(token|secret|passw|pwd|session|sess|auth|key|code|sig|signature|otp|csrf|jwt|bearer|"
    r"credential|ticket)"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_COOKIE_PAIR = re.compile(r"(?i)\b(cookie|set-cookie|authorization)\s*[:=]\s*[^\s;]+(;\s*[^\s;]+)*")
_URL = re.compile(r"https?://[^\s<>\"']+")


def redact_url(url: str) -> str:
    """Blanks the values of credential-looking query parameters and any
    user:password@ part; everything else is kept so the URL stays useful."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        # A plain ASCII marker, swapped for REDACTED afterwards: urlencode would
        # percent-escape the «» characters.
        query = urlencode(
            [(k, "xredactedx" if _SENSITIVE_PARAM.search(k) and v else v) for k, v in pairs]
        ).replace("xredactedx", REDACTED)
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Redacts known secret values, URL credentials, bearer tokens, JWTs and
    cookie/authorization header values from free text."""
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, REDACTED)
    text = _URL.sub(lambda m: redact_url(m.group(0)), text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _COOKIE_PAIR.sub(lambda m: f"{m.group(1)}: {REDACTED}", text)
    return _JWT.sub(REDACTED, text)
