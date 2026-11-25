"""Wordlists for directory/file brute forcing.

Two lists exist:

* ``sentinel-core``: Sentinel's own list (``category<TAB>path`` per line).
* ``seclists-common``: SecLists ``Discovery/Web-Content/common.txt`` (one path per
  line), vendored if it could be downloaded. When the file is absent ``load``
  returns ``None`` and the worker falls back to ``sentinel-core``.

The files ship inside the wheel (hatch packages the whole ``sentinel_recon``
directory), so they are read with ``importlib.resources``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources

CATEGORIES: frozenset[str] = frozenset({"config", "backup", "vcs", "admin", "api"})
COMMON_CATEGORY = "common"
MAX_PATH_LENGTH = 200

# Entries ending in one of these are archives or dumps. They are never fetched by
# ffuf; the worker checks them with a guarded HEAD request instead.
ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".gz",
    ".bz2",
    ".7z",
    ".rar",
    ".sql",
    ".sql.gz",
    ".dump",
    ".db",
    ".sqlite",
)

# Wordlist name -> file name inside this package.
_FILES: dict[str, str] = {
    "sentinel-core": "sentinel-core.txt",
    "seclists-common": "seclists-common.txt",
}


@dataclass(frozen=True, slots=True)
class Entry:
    category: str
    path: str


@dataclass(frozen=True, slots=True)
class Wordlist:
    name: str
    sha256: str
    entries: list[Entry]
    # Entries left out of ``entries`` by the state-changing-word screen.
    skipped_state_changing: int = 0


# Words that name an action which could change state when requested with a plain
# GET (log out, delete, install, upload, reset, register, ...). Brute force asks
# for every path with GET on live client sites, so an entry containing one of
# these as a word is never requested, whatever list it came from. Applied in
# ``load`` to every list (the curated one has none by construction; SecLists
# common.txt does). The DestructiveActionGuard is a second, separate screen.
STATE_CHANGING_WORDS: frozenset[str] = frozenset(
    {
        "logout",
        "logoff",
        "signout",
        "delete",
        "remove",
        "destroy",
        "reset",
        "drop",
        "purge",
        "cancel",
        "unsubscribe",
        "checkout",
        "pay",
        "buy",
        "order",
        "orders",
        "upload",
        "install",
        "setup",
        "upgrade",
        "update",
        "shutdown",
        "restart",
        "kill",
        "flush",
        "clear",
        "wipe",
        "cron",
        "execute",
        "exec",
        "import",
        "send",
        "forgot",
        "lostpassword",
        "recover",
        "reminder",
        "register",
        "signup",
        "subscribe",
        "activate",
        "confirm",
        "verify",
        "approve",
        "invite",
        "unlock",
        "restore",
        "rollback",
        "generate",
        "regenerate",
        "revoke",
        "terminate",
        "truncate",
        "heapdump",
        "shell",
        "cmd",
        "eval",
        "backdoor",
    }
)


def looks_state_changing(path: str) -> bool:
    """True when any word of ``path`` (split on non-alphanumerics, lower case)
    is a state-changing word."""
    return not STATE_CHANGING_WORDS.isdisjoint(re.findall(r"[a-z0-9]+", path.lower()))


def is_archive(path: str) -> bool:
    """True when ``path`` ends in an archive/dump suffix (case-insensitive)."""
    return path.lower().endswith(ARCHIVE_SUFFIXES)


def path_problem(path: str) -> str | None:
    """Why ``path`` may not be used as a wordlist entry, or None when it is fine."""
    if not path:
        return "empty"
    if path.startswith("/"):
        return "leading slash"
    if not path.isascii():
        return "non-ASCII"
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return "whitespace or control character"
    for bad in ("#", "?", "%", ".."):
        if bad in path:
            return f"contains {bad!r}"
    if "FUZZ" in path:
        return "contains FUZZ"
    if len(path) > MAX_PATH_LENGTH:
        return "too long"
    return None


def _parse(name: str, text: str) -> tuple[list[Entry], list[str]]:
    """Parse a wordlist file. Returns (entries, rejected lines).

    Blank lines and ``#`` comment lines are ignored (they are not "rejected").
    Malformed lines (bad format, unknown category, a path that breaks the entry
    rules, a duplicate path) are skipped and reported so that tests can insist the
    shipped files have none.
    """
    entries: list[Entry] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in text.split("\n"):
        line = raw.removesuffix("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if name == "seclists-common":
            category, path = COMMON_CATEGORY, line
        else:
            category, sep, path = line.partition("\t")
            if not sep or category not in CATEGORIES:
                rejected.append(line)
                continue
        if path_problem(path) is not None or path in seen:
            rejected.append(line)
            continue
        seen.add(path)
        entries.append(Entry(category=category, path=path))
    return entries, rejected


def _read_bytes(filename: str) -> bytes | None:
    try:
        return resources.files(__name__).joinpath(filename).read_bytes()
    except (FileNotFoundError, NotADirectoryError, OSError):
        return None


def _load_raw(name: str) -> tuple[bytes, list[Entry], list[str]] | None:
    filename = _FILES.get(name)
    if filename is None:
        return None
    data = _read_bytes(filename)
    if data is None:
        return None
    entries, rejected = _parse(name, data.decode("utf-8", errors="replace"))
    return data, entries, rejected


@cache
def load(name: str) -> Wordlist | None:
    """Load a wordlist by name. Unknown name or missing file gives None. Cached."""
    raw = _load_raw(name)
    if raw is None:
        return None
    data, entries, _rejected = raw
    safe = [e for e in entries if not looks_state_changing(e.path)]
    return Wordlist(
        name=name,
        sha256=hashlib.sha256(data).hexdigest(),
        entries=safe,
        skipped_state_changing=len(entries) - len(safe),
    )
