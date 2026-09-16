"""Shared browser-launch config. Playwright normally auto-detects its
cached browser via PLAYWRIGHT_BROWSERS_PATH, but that cache can hold an
older Chromium revision than the installed `playwright` package expects —
its default headless launch then looks for a *different* revision's
headless-shell binary and fails, even though a perfectly good Chromium is
sitting right there. Passing the real chromium binary's path explicitly
(with headless=True, which the full binary supports natively) sidesteps
that revision-matching entirely.
"""

from __future__ import annotations

import os

# Override for environments (like this one) whose pre-installed Chromium
# cache predates the installed playwright package. Leave unset in a normal
# deployment that ran `playwright install` itself.
CHROMIUM_EXECUTABLE_PATH = os.environ.get("SENTINEL_CHROMIUM_PATH") or None


def chromium_launch_kwargs() -> dict:
    kwargs: dict = {"headless": True}
    if CHROMIUM_EXECUTABLE_PATH:
        kwargs["executable_path"] = CHROMIUM_EXECUTABLE_PATH
    return kwargs
