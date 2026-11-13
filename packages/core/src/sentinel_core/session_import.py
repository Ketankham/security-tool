"""Cookie and header logins (v1 #1): for sites a form recipe can't drive
(CAPTCHA, SSO, OTP), the tester logs in by hand and pastes the session.

- **cookie**: the value of the browser's ``Cookie`` request header, copied
  from the dev tools (``name=value; name2=value2``);
- **header**: one request header, e.g. ``Authorization: Bearer eyJ...``.

Both the API (when the login is saved) and the worker (before it uses one)
go through these functions, so a value that would break a request (or smuggle
a second header via a line break) is refused up front.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from .login_safety import host_is_on_target

# RFC 9110 token: what a header or cookie name may consist of.
_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

# Headers the browser or the HTTP client manages itself; overriding them
# would break requests rather than authenticate them. Use the cookie login
# for cookies.
FORBIDDEN_HEADER_NAMES = frozenset(
    {
        "host",
        "cookie",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
        "trailer",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
    }
)


def _has_control_chars(value: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in value if c != "\t")


def parse_cookie_header(raw: str) -> list[tuple[str, str]]:
    """``"a=1; b=2"`` -> ``[("a", "1"), ("b", "2")]``.

    Tolerates a leading ``Cookie:`` (copied with the header name), blank
    segments and surrounding whitespace. Raises ValueError with a readable
    message when there is no usable cookie or a part is malformed."""
    text = raw.strip()
    if text.lower().startswith("cookie:"):
        text = text[len("cookie:") :].strip()
    if not text:
        raise ValueError("Paste at least one cookie, e.g. sessionid=abc123")
    if _has_control_chars(text):
        raise ValueError("The cookie value must be on a single line.")

    cookies: list[tuple[str, str]] = []
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ValueError(f"'{part[:40]}' is not a name=value cookie.")
        if not _TOKEN_RE.match(name):
            raise ValueError(f"'{name[:40]}' is not a valid cookie name.")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        cookies.append((name, value))
    if not cookies:
        raise ValueError("Paste at least one cookie, e.g. sessionid=abc123")
    return cookies


def check_header_name(name: str) -> str:
    """Returns the trimmed header name or raises ValueError."""
    name = name.strip()
    if not name:
        raise ValueError("Enter the header name, e.g. Authorization")
    if not _TOKEN_RE.match(name):
        raise ValueError(f"'{name[:40]}' is not a valid header name.")
    if name.lower() in FORBIDDEN_HEADER_NAMES:
        hint = " Use the cookie login for cookies." if name.lower() == "cookie" else ""
        raise ValueError(f"The '{name}' header can't be used for logging in.{hint}")
    return name


def check_header_value(value: str, header_name: str | None = None) -> str:
    """Returns the trimmed header value or raises ValueError. Tolerates the
    header name pasted in front (``Authorization: Bearer x``)."""
    text = value.strip()
    if header_name and text.lower().startswith(header_name.strip().lower() + ":"):
        text = text[len(header_name.strip()) + 1 :].strip()
    if not text:
        raise ValueError("Paste the header value, e.g. Bearer eyJhbGci...")
    if _has_control_chars(text):
        raise ValueError("The header value must be on a single line.")
    return text


# --- carrying a header login through a scan -----------------------------------

# A header login has no cookie for Playwright's storage_state to carry, so the
# header rides along in the persona's (encrypted) session state under this
# key. ``split_session_state`` strips it back out before the state is handed
# to Playwright.
SESSION_HEADERS_KEY = "sentinel_headers"


def split_session_state(state: dict | None) -> tuple[dict | None, dict[str, str]]:
    """(Playwright storage_state without our key, extra headers)."""
    if not state:
        return state, {}
    headers = dict(state.get(SESSION_HEADERS_KEY) or {})
    if SESSION_HEADERS_KEY not in state:
        return state, headers
    return {k: v for k, v in state.items() if k != SESSION_HEADERS_KEY}, headers


async def route_session_headers(
    context: Any, headers: dict[str, str], target_root_domain: str
) -> None:
    """Add ``headers`` to every request a Playwright browser context makes
    to the target's own hosts, and to nothing else. (Playwright's
    ``extra_http_headers`` would also send the token to every CDN,
    analytics and font host the page loads.)"""
    if not headers:
        return
    lowered = {k.lower() for k in headers}

    async def _handle(route: Any, request: Any) -> None:
        host = urlsplit(request.url).hostname or ""
        if not host_is_on_target(host, target_root_domain):
            await route.continue_()
            return
        merged = {
            k: v for k, v in (await request.all_headers()).items() if k.lower() not in lowered
        }
        merged.update(headers)
        await route.continue_(headers=merged)

    await context.route("**/*", _handle)
