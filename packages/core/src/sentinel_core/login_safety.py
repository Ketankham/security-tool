"""Where a login recipe may send the browser (QA bug log 2026-11-12, #23).

A login recipe types a persona's real password into whatever page it opens.
Before this check, `javascript:alert(1)` or `https://evil.example.org/login`
could be saved as the login URL, and the worker would then fill the stored
password into that page. Both the API (when a recipe is saved) and the
worker (right before it replays one, which also covers recipes saved before
this check existed) call ``login_navigation_problems``.

Rule: every URL the recipe navigates to (``start_url`` and each ``goto``
step) must be http(s) with a host, and that host must be the target's root
domain or one of its subdomains. A login hosted elsewhere (SSO, e.g.
login.microsoftonline.com) is allowed only when the recipe carries an
explicit ``allow_off_domain: true``, which the dashboard sets from a
confirmation checkbox.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


def _bare_host(value: str) -> str:
    """Host of a URL or bare domain, lower-cased, without port/trailing dot.
    Tolerates targets stored before the API normalised root domains
    (e.g. "https://example.com")."""
    raw = value.strip()
    netloc = urlsplit(raw).netloc if "://" in raw else raw.split("/", 1)[0]
    host = netloc.rsplit("@", 1)[-1].split(":", 1)[0]
    return host.rstrip(".").lower()


def host_is_on_target(host: str, target_root_domain: str) -> bool:
    root = _bare_host(target_root_domain)
    host = host.rstrip(".").lower()
    return bool(root) and (host == root or host.endswith("." + root))


def login_navigation_problems(recipe: Mapping[str, Any], target_root_domain: str) -> list[str]:
    """Human-readable problems with the URLs a recipe navigates to; empty
    when the recipe is safe to replay with a real password."""
    urls: list[tuple[str, str]] = [("login page URL", str(recipe.get("start_url") or ""))]
    for i, step in enumerate(recipe.get("steps") or []):
        if step.get("action") == "goto":
            urls.append((f"step {i + 1} (goto)", str(step.get("value") or "")))

    allow_off_domain = bool(recipe.get("allow_off_domain"))
    root = _bare_host(target_root_domain)
    problems: list[str] = []
    for where, url in urls:
        parts = urlsplit(url.strip())
        if parts.scheme.lower() not in ("http", "https"):
            problems.append(f"{where} must start with http:// or https:// (got {url!r})")
            continue
        host = (parts.hostname or "").lower()
        if not host:
            problems.append(f"{where} has no host name (got {url!r})")
            continue
        if not allow_off_domain and not host_is_on_target(host, target_root_domain):
            problems.append(
                f"{where} is on {host}, not on {root} or its subdomains. If this is the "
                "client's real login (e.g. SSO), confirm the other domain explicitly "
                "(allow_off_domain)."
            )
    return problems
