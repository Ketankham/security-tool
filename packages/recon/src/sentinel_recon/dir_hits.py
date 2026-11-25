"""Deciding which ffuf hits are real: pure functions, no I/O.

ffuf reports every path that answered with something other than 404 (after its
own calibration). Real sites still produce noise: a catch-all that answers 200
or redirects to /login for any path, custom "not found" pages with a 403, and
rate limiting that shows up as 429/503. This module applies the rules that
turn that into a short list of paths worth showing, and notices when the host
is answering everything (``catch_all``) so the caller can say so.

Baselines are what the host answers for paths that cannot exist (the
calibration strings): a baseline response's (status, words, lines) and
redirect target. A hit that looks exactly like a baseline is the host's
default answer, not a discovery.
"""

from __future__ import annotations

import random
import secrets
import string
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .ffuf_wrapper import FfufHit

# Statuses that mean "something is there" (or is there but protected).
KEEP_STATUSES: frozenset[int] = frozenset(
    {*range(200, 300), 301, 302, 303, 307, 308, 401, 403, 405, 500}
)
# Statuses that mean "slow down": counted by BackpressureMonitor, never kept.
BACKPRESSURE: frozenset[int] = frozenset({429, 503})

MAX_BACKPRESSURE_TOTAL = 10
MAX_BACKPRESSURE_CONSECUTIVE = 5

# More kept hits than this share of the wordlist (and at least this many) means
# the host is answering almost everything: calibration did not catch it.
CATCH_ALL_MIN_HITS = 50
CATCH_ALL_FRACTION = 0.30

DROP_STATUS = "status_not_kept"
DROP_BACKPRESSURE = "backpressure"
DROP_BASELINE = "baseline"
DROP_REDIRECT = "redirect_baseline"


class BackpressureMonitor:
    """Stops a run that the host is pushing back on. Feed it the status of
    every hit; ``observe`` returns False once ffuf should be stopped: 10
    backpressure responses in total, or 5 in a row. A hit with any other status
    resets the run of consecutive ones."""

    def __init__(
        self,
        *,
        max_total: int = MAX_BACKPRESSURE_TOTAL,
        max_consecutive: int = MAX_BACKPRESSURE_CONSECUTIVE,
    ) -> None:
        self._max_total = max_total
        self._max_consecutive = max_consecutive
        self.total = 0
        self.consecutive = 0
        self.stopped = False

    def observe(self, status: int) -> bool:
        """True to keep going, False to stop the run (and keep returning False)."""
        if status in BACKPRESSURE:
            self.total += 1
            self.consecutive += 1
            if self.total >= self._max_total or self.consecutive >= self._max_consecutive:
                self.stopped = True
        else:
            self.consecutive = 0
        return not self.stopped

    @property
    def reason(self) -> str | None:
        if not self.stopped:
            return None
        statuses = "/".join(str(s) for s in sorted(BACKPRESSURE))
        return (
            f"the host pushed back ({self.total} responses of {statuses}, "
            f"{self.consecutive} in a row)"
        )


@dataclass(frozen=True, slots=True)
class Baseline:
    """How the host answers a path that does not exist."""

    status: int
    words: int
    lines: int
    redirect: str = ""  # Location header as sent, "" when none
    url: str = ""  # the URL requested, to resolve a relative redirect against


def baseline_from_response(status: int, body: bytes, location: str | None, url: str) -> Baseline:
    """A Baseline from an ordinary HTTP response, counted the way ffuf counts
    (words = spaces + 1, lines = newlines + 1) so the two are comparable."""
    return Baseline(
        status=status,
        words=body.count(b" ") + 1,
        lines=body.count(b"\n") + 1,
        redirect=location or "",
        url=url,
    )


def normalise_redirect(
    location: str, request_url: str, site_hosts: Collection[str] = ()
) -> str | None:
    """A redirect target in comparable form: resolved against the request URL,
    query string and fragment removed, and for the site itself (the request's
    own host and ``site_hosts``, e.g. the real name when the request went to a
    pinned IP) reduced to just the path. Scheme is ignored, so http->https of
    the same path compares equal. None when there is no usable target."""
    if not location or not location.strip():
        return None
    try:
        joined = urljoin(request_url, location.strip())
        parts = urlsplit(joined)
        own = urlsplit(request_url).hostname
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    sites = {h.lower() for h in site_hosts}
    if own:
        sites.add(own.lower())
    path = parts.path or "/"
    if not host or host in sites:
        return path
    return f"//{host}{f':{port}' if port else ''}{path}"


def filter_hits(
    hits: Iterable[FfufHit],
    baselines: Iterable[Baseline],
    entries_count: int,
    *,
    site_hosts: Collection[str] = (),
) -> tuple[list[FfufHit], dict[str, int], bool]:
    """Returns ``(kept, dropped_counts, catch_all)``.

    A hit is dropped when
    - its status is not in KEEP_STATUSES (``status_not_kept``; the backpressure
      statuses 429/503 are counted under ``backpressure``),
    - its (status, words, lines) equals a baseline's (``baseline``), or
    - it redirects to the same normalised target as a baseline does
      (``redirect_baseline``): ``normalise_redirect`` resolves it against the
      request URL and removes the query string, so ``/login?next=/x`` and
      ``https://site/login`` both equal a baseline that redirects to ``/login``.

    ``catch_all`` is True when more than max(50, 30% of ``entries_count``) hits
    survive: the host answers nearly everything, so even the kept list should
    not be trusted. ``kept`` is returned either way (order preserved) and the
    caller decides what to do with it.
    """
    baseline_list = list(baselines)
    baseline_shapes = {(b.status, b.words, b.lines) for b in baseline_list}
    baseline_redirects = {
        target
        for b in baseline_list
        if (target := normalise_redirect(b.redirect, b.url, site_hosts)) is not None
    }
    kept: list[FfufHit] = []
    dropped: dict[str, int] = {}

    def drop(reason: str) -> None:
        dropped[reason] = dropped.get(reason, 0) + 1

    for hit in hits:
        if hit.status in BACKPRESSURE:
            drop(DROP_BACKPRESSURE)
        elif hit.status not in KEEP_STATUSES:
            drop(DROP_STATUS)
        elif (hit.status, hit.words, hit.lines) in baseline_shapes:
            drop(DROP_BASELINE)
        elif (
            hit.redirect
            and baseline_redirects
            and normalise_redirect(hit.redirect, hit.url, site_hosts) in baseline_redirects
        ):
            drop(DROP_REDIRECT)
        else:
            kept.append(hit)
    catch_all = len(kept) > max(CATCH_ALL_MIN_HITS, CATCH_ALL_FRACTION * entries_count)
    return kept, dropped, catch_all


CAL_PREFIX = "sentinelcal"
CAL_LENGTHS = (12, 20, 28)
_ALPHABET = string.ascii_lowercase + string.digits


def calibration_strings(rng: random.Random | None = None) -> list[str]:
    """Paths that cannot exist, to learn how the host answers them.

    Five strings, in this order: ``sentinelcal`` plus 12, 20 and 28 random
    characters (different lengths, so a page that echoes the path varies the
    way ffuf's calibration needs), the 20-character one again with a different
    random part and a trailing "/" (how a directory is answered), and a dotfile
    ``.sentinelcal`` plus 12 random characters. Random parts are lowercase
    letters and digits, so every string is URL-safe; only the one directory
    variant contains a "/", at its end. Uses ``secrets`` unless a seeded
    ``random.Random`` is passed (tests).
    """

    def rand(n: int) -> str:
        if rng is not None:
            return "".join(rng.choice(_ALPHABET) for _ in range(n))
        return "".join(secrets.choice(_ALPHABET) for _ in range(n))

    return [
        *(f"{CAL_PREFIX}{rand(n)}" for n in CAL_LENGTHS),
        f"{CAL_PREFIX}{rand(CAL_LENGTHS[1])}/",
        f".{CAL_PREFIX}{rand(CAL_LENGTHS[0])}",
    ]
