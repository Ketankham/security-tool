"""Secret scrubbing (docs/01-architecture.md §6.3 rule 4).

Applied to every transcript on write. This is a defence-in-depth layer, not
the only one: credentials never reach an LLM prompt and are decrypted only
in-memory (see sentinel_core.crypto) — but transcripts get read by humans in
the UI and exported in reports, so redact here too.
"""

from __future__ import annotations

import re

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

REDACTED = "«redacted»"

# Common credential-shaped values worth catching even outside a known header
# (e.g. a token echoed into a JSON body). Deliberately conservative to avoid
# mangling legitimate response content.
_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"(?i)\bsk-[A-Za-z0-9]{20,}\b"),  # generic secret-key-shaped token
]


def scrub_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if k.lower() in SENSITIVE_HEADER_NAMES else v) for k, v in headers.items()}


def scrub_body(body: bytes | None, *, known_secrets: list[str] | None = None) -> bytes | None:
    if body is None:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body  # binary payload (upload, image) — leave alone

    for secret in known_secrets or []:
        if secret:
            text = text.replace(secret, REDACTED)

    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)

    return text.encode("utf-8")
