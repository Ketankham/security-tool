"""ffuf wrapper (MIT, ffuf/ffuf): directory and file brute forcing. Unlike the
passive recon tools this one sends many requests to the target, so it only runs
for scans the user has explicitly authorised (see the worker's active-tools
gate) and only ever with the argument list ``build_args`` returns.

What ffuf is deliberately *not* allowed to do here, and why:

- no recursion (``-recursion``), no redirect following (``-r``), no custom
  method or body (``-X``, ``-d``), no external command input (``-input-cmd``),
  no pre-flight or audit files (``-preflight``, ``-od``, ``-audit-log``): the
  wordlist is the complete list of paths we are willing to request;
- calibration (``-ac``) is given our own ``-acc`` strings so the only
  calibration requests are ones the caller has already checked against the
  scan's scope rules (ffuf's built-in ``admin<random>`` / ``.htaccess<random>``
  could hit an excluded path);
- ``-sa`` makes it stop itself on 429/403 floods and connection errors, and
  ``-rate`` / ``-t 2`` / ``-maxtime`` bound its speed and duration;
- each run gets a private HOME / XDG_CONFIG_HOME / cwd so it can never read a
  stray ``ffufrc`` or leave history behind.

Known ffuf v2.3.0 facts this relies on (verified against the real binary):
``-acc`` only works together with ``-ac``; ``-V`` misreports the version (it
prints 2.1.0-dev), so the image records the version at build time; the exit
code is 0 even when ffuf stops itself, so a stop is recognised from stderr;
``-json`` reports the input in ``input.FUZZ`` as base64.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_core.http_engine import USER_AGENT

from .tooling import STOPPED_BY_CALLER, ToolRunResult, run_tool

BINARY = "ffuf"
# Written by the worker image build (infra/docker/Dockerfile.worker).
VERSION_FILE = Path("/usr/local/share/sentinel-tools/ffuf.version")

# Safety net on memory: a wordlist is a few thousand entries at most, so a run
# that reports more hits than this is broken (e.g. a catch-all that calibration
# missed) and is stopped.
MAX_HITS = 20_000
TOO_MANY_HITS = "too many results (the host answers almost every path)"
STOPPED_BY_FILTER = "stopped by the hit filter"

_VERSION_TOKEN = re.compile(r"ffuf version:\s*(\S+)", re.IGNORECASE)


async def version() -> str | None:
    """The ffuf version, e.g. "v2.3.0". Never raises.

    ``ffuf -V`` prints "2.1.0-dev" for the v2.3.0 release, so the image build
    writes the real module version to VERSION_FILE; ``-V`` is only the fallback
    (a dev machine with a hand-built binary) and is returned as reported."""
    try:
        text = VERSION_FILE.read_text().strip()
        if text:
            return text.splitlines()[0].strip()
    except OSError:
        pass
    try:
        result = await run_tool(BINARY, ["-V"], timeout_s=5.0)
    except Exception:  # noqa: BLE001 — a version string is never worth a failed scan
        return None
    if not result.ran or result.timed_out:
        return None
    match = _VERSION_TOKEN.search(result.stdout + result.stderr)
    if not match:
        return None
    token = match.group(1)
    return token if token.startswith("v") else f"v{token}"


def build_args(
    base_url: str,
    wordlist_file: str,
    cal_strings: list[str],
    rps: float,
    maxtime: int,
    host_header: str | None = None,
    sni: str | None = None,
) -> list[str]:
    """The complete ffuf argument list. Golden-tested: do not add flags
    without changing the tests and the reasoning in this module's docstring.

    ``base_url`` is scheme://host[:port] with no path (when the worker pins an
    IP it is the IP, with ``host_header`` / ``sni`` carrying the real name).
    ``cal_strings`` are the calibration paths (at least three, of different
    lengths: ffuf needs several to recognise a catch-all that echoes length).
    ``maxtime`` is ffuf's own whole-run limit in seconds."""
    return [
        "-u", f"{base_url.rstrip('/')}/FUZZ",
        "-w", f"{wordlist_file}:FUZZ",
        "-H", f"User-Agent: {USER_AGENT}",
        *(["-H", f"Host: {host_header}"] if host_header else []),
        *(["-sni", sni] if sni else []),
        "-ac", *[a for c in cal_strings for a in ("-acc", c)],
        "-mc", "all", "-fc", "404", "-t", "2", "-rate", str(max(1, int(rps))),
        "-timeout", "10", "-maxtime", str(int(maxtime)), "-sa",
        "-json", "-s", "-noninteractive",
    ]  # fmt: skip


@dataclass(frozen=True, slots=True)
class FfufHit:
    path: str  # the wordlist entry, no leading "/"
    status: int
    length: int = 0
    words: int = 0
    lines: int = 0
    content_type: str = ""
    redirect: str = ""  # the Location header as sent, "" when none
    url: str = ""  # the URL ffuf requested (pinned IP and all)


def _int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def parse_line(line: str) -> FfufHit | None:
    """One ``-json`` stdout line to a hit. Blank, non-JSON or malformed lines
    (and lines without a decodable FUZZ input or a status) give None; other
    missing keys take defaults. Never raises."""
    try:
        line = line.strip()
        if not line.startswith("{"):
            return None
        doc = json.loads(line)
        if not isinstance(doc, dict):
            return None
        inputs = doc.get("input")
        fuzz = inputs.get("FUZZ") if isinstance(inputs, dict) else None
        if not isinstance(fuzz, str) or not fuzz:
            return None
        path = base64.b64decode(fuzz, validate=True).decode("utf-8", errors="replace")
        status = doc.get("status")
        if isinstance(status, bool) or not isinstance(status, int):
            return None
        return FfufHit(
            path=path,
            status=status,
            length=_int(doc.get("length")),
            words=_int(doc.get("words")),
            lines=_int(doc.get("lines")),
            content_type=_text(doc.get("content-type")),
            redirect=_text(doc.get("redirectlocation")),
            url=_text(doc.get("url")),
        )
    except (ValueError, binascii.Error, RecursionError):
        return None


# Fragment of ffuf's stderr message -> what the tester reads. Order matters
# only if two messages appear together; 429 is the one that most needs saying.
_STDERR_REASONS: tuple[tuple[str, str], ...] = (
    ("unusual amount of 429", "rate limited (429)"),
    ("403 responses", "the host answered 403 to almost everything"),
    ("spurious errors", "too many connection errors"),
    ("Maximum running time", "time limit reached (partial results)"),
)


def stop_reason_from_stderr(stderr: str) -> str | None:
    for fragment, reason in _STDERR_REASONS:
        if fragment in stderr:
            return reason
    return None


@dataclass(slots=True)
class FfufRun:
    result: ToolRunResult
    hits: list[FfufHit] = field(default_factory=list)
    # Why the run ended early, in words for the activity log: "cancelled",
    # "timed out", the hit callback's reason, or ffuf's own stop (stderr).
    # None when ffuf finished the wordlist.
    stop_reason: str | None = None


async def run_ffuf(
    args: list[str],
    *,
    timeout_s: float,
    on_hit: Callable[[FfufHit], bool] | None = None,
    cancel_check: Callable[[], Awaitable[str | None]] | None = None,
    stop_hint: Callable[[], str | None] | None = None,
    workdir: str | None = None,
) -> FfufRun:
    """Runs ffuf with ``args`` (from ``build_args``) and collects its hits.

    - Every hit is parsed and handed to ``on_hit(hit) -> bool`` as it arrives;
      False kills ffuf at once (backpressure: see dir_hits.BackpressureMonitor).
      ``stop_hint()`` may then say why, for the log.
    - ``cancel_check`` is polled about once a second (see tooling.run_tool).
    - ffuf's HOME, XDG_CONFIG_HOME and cwd are a private directory. Pass
      ``workdir`` when the caller already made one (e.g. to write the wordlist
      into it); the caller then owns and removes it. Otherwise a temporary
      directory is created and removed here.
    - Timeout, cancel, stop and any exception (CancelledError included) kill
      ffuf's whole process group before this returns or raises.
    """
    if workdir is None:
        with tempfile.TemporaryDirectory(prefix="sentinel-ffuf-") as tmp:
            return await _run(args, tmp, timeout_s, on_hit, cancel_check, stop_hint)
    return await _run(args, workdir, timeout_s, on_hit, cancel_check, stop_hint)


async def _run(
    args: list[str],
    workdir: str,
    timeout_s: float,
    on_hit: Callable[[FfufHit], bool] | None,
    cancel_check: Callable[[], Awaitable[str | None]] | None,
    stop_hint: Callable[[], str | None] | None,
) -> FfufRun:
    hits: list[FfufHit] = []
    over_limit = False

    def on_line(line: str) -> bool:
        nonlocal over_limit
        hit = parse_line(line)
        if hit is None:
            return True
        hits.append(hit)
        if len(hits) >= MAX_HITS:
            over_limit = True
            return False
        return on_hit(hit) if on_hit is not None else True

    result = await run_tool(
        BINARY,
        args,
        timeout_s=timeout_s,
        on_stdout_line=on_line,
        cancel_check=cancel_check,
        env={"HOME": workdir, "XDG_CONFIG_HOME": f"{workdir}/cfg"},
        cwd=workdir,
    )
    return FfufRun(
        result=result, hits=hits, stop_reason=_stop_reason(result, over_limit, stop_hint)
    )


def _stop_reason(
    result: ToolRunResult, over_limit: bool, stop_hint: Callable[[], str | None] | None
) -> str | None:
    if not result.ran:
        return None
    if result.cancelled:
        return "cancelled"
    if result.timed_out:
        return "timed out"
    if result.stopped_reason is not None:
        if over_limit:
            return TOO_MANY_HITS
        hint = None
        if stop_hint is not None:
            try:
                hint = stop_hint()
            except Exception:  # noqa: BLE001 — a log hint must not break the run
                hint = None
        if hint:
            return hint
        # A callback that raised is reported by run_tool in its own words.
        failed = result.stopped_reason != STOPPED_BY_CALLER
        return result.stopped_reason if failed else STOPPED_BY_FILTER
    return stop_reason_from_stderr(result.stderr)
