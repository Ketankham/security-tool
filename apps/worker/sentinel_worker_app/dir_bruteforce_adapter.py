"""Directory and file brute force (ffuf), the worker side.

This is an *active* tool: it sends one request for every entry of a wordlist
to a live client host, so it only runs for a scan whose authorisation record
covers it (see active_tools.authorised_tools) and only ever sends what is
written down here. The rules that keep it safe, each enforced in code and
covered by a test:

- every path that reaches ffuf was first checked with the scope guard (GET) and
  the destructive-action screen; the same check removes calibration strings.
  Nothing else is ever written to ffuf's wordlist file;
- archive and dump names (.zip, .sql, ...) are never given to ffuf: they are
  checked with HEAD requests made through the guarded HTTP engine, so a large
  file is never downloaded;
- ffuf is pinned to the IP recon resolved, with the real name in the Host header
  and SNI, and that IP is checked again here (unless private addresses are
  allowed for this deployment);
- the file signature of a hit (a .env, a Git HEAD) is checked by fetching it
  through the HTTP engine, with the body withheld from storage for anything
  that may hold secrets; only names, status and size are kept. Finding
  confidence comes from the usual two independent reproductions;
- a host that answers every path the same way produces no rows;
- ffuf is stopped when the host pushes back (429/503 and the like), when the
  time budget runs out, and when the scan is cancelled.
"""

from __future__ import annotations

import asyncio
import ipaddress
import shlex
import tempfile
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from sentinel_checks.passive import PassiveCandidate
from sentinel_checks.passive.exposed_files import (
    Probe,
    build_candidate,
    matches_baseline,
    probe_for_path,
)
from sentinel_checks.verification import verify_candidate
from sentinel_core import scan_options
from sentinel_core.address_guard import non_public_ips
from sentinel_core.http_engine import EngineResponse, HttpEngine, ScopeViolation
from sentinel_core.redact import redact_url
from sentinel_core.scope_guard import DestructiveActionGuard, ScopeGuard
from sentinel_db.models import (
    DiscoveredPath,
    Finding,
    Scan,
    ToolRunRecord,
    TranscriptRecord,
)
from sentinel_recon import ReconResult, ToolRun, wordlists
from sentinel_recon import dir_hits as dh
from sentinel_recon import ffuf_wrapper as ffuf
from sentinel_recon.models import DiscoveredAsset
from sentinel_recon.runs import tool_run_from
from sentinel_recon.tooling import ToolRunResult, tool_available
from sqlalchemy.ext.asyncio import AsyncSession

from . import recon_adapter
from .cancel import ScanCancelled
from .passive_adapter import build_finding, candidate_fingerprint
from .scan_log import NullScanLog, ScanLog

STAGE = "dir_bruteforce"
HEAD_TOOL = "head-pass (built-in)"

MAX_ROWS_PER_HOST = 300
MAX_CRAWL_SEEDS = 20
# Do not start ffuf with less time than this left in the budget.
MIN_RUN_SECONDS = 10
# How long past ffuf's own -maxtime the subprocess may live before it is killed.
SUBPROCESS_GRACE_S = 60
EXAMPLES_IN_LOG = 3

_STANDARD_PORT = {"http": 80, "https": 443}

# A ".env.example" is normally a template with placeholder values, so reporting it
# as an exposed secret file (critical) would be a false alarm. It is listed as a
# path with a note, and not fetched or turned into a finding.
TEMPLATE_SUFFIXES = (".example", ".sample", ".dist", ".default", ".template", ".tpl")

Log = ScanLog | NullScanLog
Clock = Callable[[], float]
WordlistLoader = Callable[[str], "wordlists.Wordlist | None"]


class _Cancel(Protocol):
    """What this step needs from a cancel.CancelWatch."""

    async def requested(self) -> str | None: ...

    async def raise_if_cancelled(self) -> None: ...


@dataclass(slots=True)
class DirStats:
    """What the step did. ``as_dict`` is the RECON phase's "dir_bruteforce" stats."""

    hosts_planned: int = 0
    hosts_run: int = 0
    entries: int = 0
    entries_removed_by_scope: int = 0
    entries_removed_by_safety_screen: int = 0
    wordlist: str = ""
    wordlist_sha256: str = ""
    hits: int = 0
    confirmed: int = 0
    stopped_hosts: int = 0
    not_run_hosts: int = 0
    # Where the next ToolRunRecord.seq starts.
    next_seq: int = 1
    # Fingerprints of the findings this step confirmed (passive checks skip them).
    confirmed_fingerprints: set[str] = field(default_factory=set)
    # Pages worth starting the crawl from (in scope, capped).
    path_seeds: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "hosts_planned": self.hosts_planned,
            "hosts_run": self.hosts_run,
            "entries": self.entries,
            "entries_removed_by_scope": self.entries_removed_by_scope,
            "entries_removed_by_safety_screen": self.entries_removed_by_safety_screen,
            "wordlist": self.wordlist,
            "wordlist_sha256": self.wordlist_sha256,
            "hits": self.hits,
            "confirmed": self.confirmed,
            "stopped_hosts": self.stopped_hosts,
            "not_run_hosts": self.not_run_hosts,
        }


@dataclass(frozen=True, slots=True)
class HostPlan:
    host: str  # the name, as recon knows it
    origin: str  # scheme://host[:port], as the site is known (never the pinned IP)
    scheme: str
    host_header: str  # host, with :port when the port is not the scheme's default
    port: int
    ip: str  # the address recon resolved: ffuf is pinned to it
    ips: tuple[str, ...]

    @property
    def pinned_base(self) -> str:
        ip = f"[{self.ip}]" if ":" in self.ip else self.ip
        port = "" if self.port == _STANDARD_PORT[self.scheme] else f":{self.port}"
        return f"{self.scheme}://{ip}{port}"

    @property
    def sni(self) -> str | None:
        if self.scheme != "https":
            return None
        return None if _is_ip_literal(self.host) else self.host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@dataclass(slots=True)
class _Row:
    """A DiscoveredPath being built."""

    entry: wordlists.Entry
    method: str
    status: int
    length: int | None
    words: int | None
    lines: int | None
    content_type: str | None
    redirect: str | None
    verdict: str = "found"
    rule_id: str | None = None
    note: str | None = None
    finding: Finding | None = None
    crawl_seed: bool = False
    from_head_pass: bool = False

    @property
    def sort_key(self) -> tuple[int, str, str]:
        order = {"confirmed": 0, "not_confirmed": 1}.get(self.verdict, 2)
        return (order, self.entry.category, self.entry.path)


# --- Choosing hosts ------------------------------------------------------------


def _answering_probe_url(asset: DiscoveredAsset) -> str | None:
    for probe in asset.http_probes:
        if probe.status_code is not None and probe.url.startswith(("http://", "https://")):
            return probe.url
    return None


def host_order(root: str, hosts: list[str]) -> list[str]:
    """The root domain first, then www, then the rest A to Z."""
    root = root.lower()
    first = [h for h in (root, f"www.{root}") if h in hosts]
    return first + sorted(h for h in hosts if h not in first)


def select_hosts(
    recon_result: ReconResult,
    *,
    scope_guard: ScopeGuard,
    allow_private: bool,
    max_hosts: int,
) -> tuple[list[HostPlan], list[str], list[str]]:
    """``(hosts to run, skipped with reasons, left out over the cap)``.

    Live, in-scope hosts, root then www then A to Z. A host is skipped when the
    scope guard refuses its front page, or when any address recon found for it
    is non-public (unless private addresses are allowed here)."""
    by_host = {a.host.lower(): a for a in recon_result.live_assets}
    eligible: list[HostPlan] = []
    skipped: list[str] = []
    for host in host_order(recon_result.root_domain, list(by_host)):
        asset = by_host[host]
        url = _answering_probe_url(asset)
        if url is None:
            continue
        parts = urlsplit(url)
        scheme = parts.scheme
        try:
            port = parts.port or _STANDARD_PORT[scheme]
        except ValueError:
            skipped.append(f"{host}: its address {url} is not usable")
            continue
        default = _STANDARD_PORT[scheme]
        # The same spelling the crawler and the passive checks use for an origin
        # (no default port), so findings from different steps share a fingerprint.
        shown_host = f"[{parts.hostname}]" if ":" in (parts.hostname or "") else parts.hostname
        port_part = f":{port}" if port != default else ""
        origin = f"{scheme}://{shown_host}{port_part}"
        decision = scope_guard.evaluate(method="GET", url=origin + "/")
        if not decision.allowed:
            skipped.append(f"{host}: {decision.reason}")
            continue
        ips = [ip for ip in asset.ips if ip]
        if not ips:
            skipped.append(f"{host}: recon found no address for it")
            continue
        bad = non_public_ips(ips)
        if bad and not allow_private:
            skipped.append(
                f"{host}: it resolves to a non-public address ({', '.join(bad)}); "
                "scans do not send requests to internal addresses"
            )
            continue
        eligible.append(
            HostPlan(
                host=host,
                origin=origin,
                scheme=scheme,
                host_header=f"{host}{port_part}",
                port=port,
                ip=ips[0],
                ips=tuple(ips),
            )
        )
    return eligible[:max_hosts], skipped, [h.host for h in eligible[max_hosts:]]


# --- What may be sent -----------------------------------------------------------


def allowed_paths(
    paths: list[str],
    *,
    origin: str,
    scope_guard: ScopeGuard,
    destructive: DestructiveActionGuard | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """``(allowed, removed by scope rules, removed by the destructive screen)``.

    The single gate between a wordlist and the network: a path is allowed only
    when a GET of ``origin + "/" + path`` passes the scope guard (host and path
    rules) and the destructive-action screen. Used for the wordlist file and
    for the calibration strings."""
    destructive = destructive or DestructiveActionGuard()
    allowed: list[str] = []
    by_scope: list[str] = []
    by_screen: list[str] = []
    for path in paths:
        url = f"{origin}/{path}"
        if not scope_guard.evaluate(method="GET", url=url).allowed:
            by_scope.append(path)
        elif destructive.check(method="GET", url=url).is_suspect:
            by_screen.append(path)
        else:
            allowed.append(path)
    return allowed, by_scope, by_screen


def _examples(paths: list[str]) -> str:
    shown = ", ".join(f"/{p}" for p in paths[:EXAMPLES_IN_LOG])
    return shown + (" …" if len(paths) > EXAMPLES_IN_LOG else "")


# --- The step ------------------------------------------------------------------


def _degrade(scan: Scan, log: Log, message: str) -> None:
    log.add(STAGE, message, level="warn")
    scan.is_degraded = True
    scan.degraded_reasons = [*scan.degraded_reasons, message]


class _EngineFetch:
    """Requests through the scan's HttpEngine that never raise for an
    out-of-scope or unreachable URL (same contract as PassiveContext.fetch)."""

    def __init__(self, engine: HttpEngine, rps: float, clock: Clock = time.monotonic) -> None:
        self._engine = engine
        self._interval = 1.0 / max(rps, 0.1)
        self._clock = clock
        self._next_at = 0.0
        self.requests = 0
        self.out_of_scope = 0
        self.last_error: str | None = None

    async def _pace(self) -> None:
        """One request per 1/rps seconds from this step. The engine's own rate
        limiter allows a short burst after a pause; a client that asked for a
        gentle scan should not see one, so this step does not use it."""
        now = self._clock()
        wait = self._next_at - now
        self._next_at = max(now, self._next_at) + self._interval
        if wait > 0:
            await asyncio.sleep(wait)

    async def __call__(self, method: str, url: str, **kwargs) -> EngineResponse | None:
        await self._pace()
        try:
            response = await self._engine.request(method, url, **kwargs)
        except ScopeViolation as exc:
            self.out_of_scope += 1
            self.last_error = f"outside the scan's scope ({exc})"
            return None
        except ConnectionError as exc:
            self.last_error = str(exc)
            return None
        self.requests += 1
        self.last_error = None
        return response


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


async def run_dir_bruteforce(
    session: AsyncSession,
    scan: Scan,
    target,
    recon_result: ReconResult,
    scope_guard: ScopeGuard,
    engine: HttpEngine,
    profile: str,
    rps: float,
    cancel: _Cancel,
    log: Log,
    seq: int,
    *,
    authorised_by: str = "unknown",
    wordlist_name: str | None = None,
    allow_private: bool = False,
    load_wordlist: WordlistLoader | None = None,
    budget_s: float | None = None,
    host_cap_s: float | None = None,
    max_hosts: int | None = None,
    clock: Clock = time.monotonic,
) -> DirStats:
    """Runs the step for ``scan`` and returns what it did. ``seq`` is the next
    free ToolRunRecord.seq (recon's runs come first). Rows, findings and tool
    runs are committed after each host, so a crash or a cancel keeps what was
    already found.

    Raises ScanCancelled (from ``cancel``) when the scan is cancelled."""
    stats = DirStats(next_seq=seq)
    profile = "full" if profile == "full" else "light"
    budget = float(budget_s if budget_s is not None else scan_options.DIR_BUDGET_S[profile])
    per_host_cap = float(
        host_cap_s if host_cap_s is not None else scan_options.DIR_HOST_CAP_S[profile]
    )
    cap_hosts = max_hosts if max_hosts is not None else scan_options.DIR_MAX_HOSTS[profile]
    loader = load_wordlist or wordlists.load
    started = clock()

    # --- 2 (first part): which wordlist -------------------------------------
    requested = wordlist_name or scan_options.resolve_wordlist(scan.options)
    wordlist = loader(requested)
    if wordlist is None and requested != "sentinel-core":
        log.add(
            STAGE,
            f"The {requested} wordlist is not available in this build; using sentinel-core "
            "instead.",
            level="warn",
        )
        wordlist = loader("sentinel-core")
    if wordlist is None:
        _degrade(scan, log, "Directory brute force did not run: no wordlist could be loaded.")
        await session.commit()
        return stats
    stats.wordlist = wordlist.name
    stats.wordlist_sha256 = wordlist.sha256
    stats.entries = len(wordlist.entries)
    if wordlist.skipped_state_changing:
        log.add(
            STAGE,
            f"{wordlist.skipped_state_changing} entr(ies) of the {wordlist.name} wordlist were "
            "left out because their names suggest an action (log out, delete, install, ...).",
        )

    # --- 1: hosts ------------------------------------------------------------
    hosts, skipped, over_cap = select_hosts(
        recon_result, scope_guard=scope_guard, allow_private=allow_private, max_hosts=cap_hosts
    )
    for reason in skipped:
        log.add(STAGE, f"Not run: {reason}.", level="warn")
    if over_cap:
        stats.not_run_hosts += len(over_cap)
        log.add(
            STAGE,
            f"Not run: {', '.join(over_cap)} (over the limit of {cap_hosts} hosts per scan).",
            level="warn",
        )
    stats.hosts_planned = len(hosts)
    if not hosts:
        log.add(STAGE, "Directory brute force: no live, in-scope host to run it on.", level="warn")
        await session.commit()
        return stats

    # --- (g) ffuf installed? -------------------------------------------------
    if not tool_available(ffuf.BINARY):
        missing = ToolRunResult(ran=False, command=ffuf.BINARY)
        record = _tool_record(
            scan,
            stats,
            tool_run_from("ffuf", missing, binary="ffuf", version=None, results_count=0),
        )
        session.add(record)
        stats.not_run_hosts += len(hosts)
        _degrade(
            scan,
            log,
            "Directory brute force did not run: ffuf is not installed on the worker.",
        )
        await session.commit()
        return stats

    log.add(
        STAGE,
        f"Directory brute force on {len(hosts)} host(s) with {wordlist.name} "
        f"({len(wordlist.entries)} entries, sha256 {wordlist.sha256[:12]}), {rps:g} req/s, "
        f"one host at a time. Authorised by {authorised_by}.",
    )

    ffuf_version = await ffuf.version()
    fetch = _EngineFetch(engine, rps)
    transcripts: dict[str, TranscriptRecord] = {}
    backpressured_in_a_row = 0
    stop_everything: str | None = None

    for index, plan in enumerate(hosts):
        await cancel.raise_if_cancelled()
        remaining = budget - (clock() - started)
        if stop_everything is None and remaining < MIN_RUN_SECONDS:
            stop_everything = "time budget"
        if stop_everything is not None:
            left = [h.host for h in hosts[index:]]
            stats.not_run_hosts += len(left)
            log.add(STAGE, f"Not run: {', '.join(left)} ({stop_everything}).", level="warn")
            if stop_everything == "time budget":
                _degrade(
                    scan,
                    log,
                    f"Directory brute force ran out of time (budget {budget / 60:g} min); "
                    f"not run: {', '.join(left)}.",
                )
            break

        outcome = await _run_host(
            session=session,
            scan=scan,
            plan=plan,
            wordlist=wordlist,
            scope_guard=scope_guard,
            fetch=fetch,
            rps=rps,
            maxtime=int(min(per_host_cap, remaining)),
            cancel=cancel,
            log=log,
            stats=stats,
            transcripts=transcripts,
            ffuf_version=ffuf_version,
            budget_left=lambda: budget - (clock() - started),
        )
        if outcome.ran:
            stats.hosts_run += 1
        if outcome.stopped:
            stats.stopped_hosts += 1
        backpressured_in_a_row = backpressured_in_a_row + 1 if outcome.backpressured else 0
        if backpressured_in_a_row >= 2 and index + 1 < len(hosts):
            stop_everything = "the previous two hosts pushed back"
            _degrade(
                scan,
                log,
                "Directory brute force stopped after two hosts in a row pushed back "
                "(rate limited or unavailable); the remaining hosts were not run.",
            )
        await session.commit()

    await session.commit()
    return stats


@dataclass(slots=True)
class _HostOutcome:
    ran: bool = False
    stopped: bool = False
    backpressured: bool = False


def _tool_record(scan: Scan, stats: DirStats, run: ToolRun) -> ToolRunRecord:
    (record,) = recon_adapter.tool_run_records(
        scan.id, [run], phase="recon", start_seq=stats.next_seq
    )
    record.id = uuid.uuid4()
    stats.next_seq += 1
    return record


async def _run_host(
    *,
    session: AsyncSession,
    scan: Scan,
    plan: HostPlan,
    wordlist: wordlists.Wordlist,
    scope_guard: ScopeGuard,
    fetch: _EngineFetch,
    rps: float,
    maxtime: int,
    cancel: _Cancel,
    log: Log,
    stats: DirStats,
    transcripts: dict[str, TranscriptRecord],
    ffuf_version: str | None,
    budget_left: Callable[[], float],
) -> _HostOutcome:
    outcome = _HostOutcome()
    origin = plan.origin
    host = plan.host

    # --- 2: what may be sent -------------------------------------------------
    get_entries = [e for e in wordlist.entries if not wordlists.is_archive(e.path)]
    archive_entries = [e for e in wordlist.entries if wordlists.is_archive(e.path)]
    all_paths = [e.path for e in wordlist.entries]
    ok_paths, by_scope, by_screen = allowed_paths(all_paths, origin=origin, scope_guard=scope_guard)
    ok = set(ok_paths)
    removed_scope = set(by_scope)
    removed_screen = set(by_screen)
    stats.entries_removed_by_scope = max(stats.entries_removed_by_scope, len(removed_scope))
    stats.entries_removed_by_safety_screen = max(
        stats.entries_removed_by_safety_screen, len(removed_screen)
    )
    if by_scope:
        log.add(
            STAGE,
            f"{host}: {len(by_scope)} entries removed by scope rules (e.g. {_examples(by_scope)}).",
        )
    if by_screen:
        log.add(
            STAGE,
            f"{host}: {len(by_screen)} entries removed by the destructive-action screen "
            f"(e.g. {_examples(by_screen)}).",
        )
    run_entries = [e for e in get_entries if e.path in ok]
    head_entries = [e for e in archive_entries if e.path in ok]
    entries_by_path = {e.path: e for e in run_entries}

    cal_all = dh.calibration_strings()
    cal, cal_by_scope, cal_by_screen = allowed_paths(
        cal_all, origin=origin, scope_guard=scope_guard
    )
    if len(cal) < 3:
        log.add(
            STAGE,
            f"Not run: {host}: fewer than 3 calibration paths are allowed by the scope rules "
            f"({len(cal_by_scope) + len(cal_by_screen)} removed), so catch-all answers could not "
            "be told apart safely.",
            level="warn",
        )
        stats.not_run_hosts += 1
        return outcome
    if not run_entries and not head_entries:
        log.add(STAGE, f"Not run: {host}: the scope rules leave no path to try.", level="warn")
        stats.not_run_hosts += 1
        return outcome

    # --- 3: how the host answers a path that cannot exist ---------------------
    await cancel.raise_if_cancelled()
    base_get1 = await fetch("GET", f"{origin}/{cal[0]}")
    base_get2 = await fetch("GET", f"{origin}/{cal[2]}")
    base_head = await fetch("HEAD", f"{origin}/{cal[1]}")
    if base_get1 is None or base_get2 is None:
        reason = fetch.last_error or "no answer"
        log.add(
            STAGE,
            f"Not run: {host}: the baseline requests did not succeed ({reason}).",
            level="warn",
        )
        stats.not_run_hosts += 1
        return outcome
    pushed_back = [r for r in (base_get1, base_get2) if r.status_code in dh.BACKPRESSURE]
    if pushed_back:
        log.add(
            STAGE,
            f"Not run: {host}: rate limited before start (it answered "
            f"{pushed_back[0].status_code} to a made-up path).",
            level="warn",
        )
        stats.not_run_hosts += 1
        stats.stopped_hosts += 1
        outcome.backpressured = True
        return outcome
    baseline_gets = [base_get1, base_get2]
    if any(r.status_code == 200 for r in baseline_gets):
        log.add(
            STAGE,
            f"{host}: a made-up path answers 200, so this host is a catch-all; only answers "
            "that differ from it are kept.",
        )
    baselines = [
        dh.baseline_from_response(r.status_code, r.body, _header(r.headers, "location"), r.url)
        for r in baseline_gets
    ]

    # --- 4/5: ffuf, pinned to the IP recon resolved ---------------------------
    kept: list[ffuf.FfufHit] = []
    dropped: dict[str, int] = {}
    catch_all = False
    ffuf_record: ToolRunRecord | None = None
    if run_entries:
        monitor = dh.BackpressureMonitor()
        with tempfile.TemporaryDirectory(prefix="sentinel-ffuf-") as workdir:
            wordlist_file = Path(workdir) / "paths.txt"
            wordlist_file.write_text("\n".join(e.path for e in run_entries) + "\n")
            args = ffuf.build_args(
                plan.pinned_base,
                str(wordlist_file),
                cal,
                rps,
                maxtime,
                host_header=plan.host_header,
                sni=plan.sni,
            )
            command = shlex.join([ffuf.BINARY, *args])
            log.add(STAGE, f"Running: {command} (pinned to {plan.ip})")
            run = await ffuf.run_ffuf(
                args,
                timeout_s=maxtime + SUBPROCESS_GRACE_S,
                on_hit=lambda hit: monitor.observe(hit.status),
                cancel_check=cancel.requested,
                stop_hint=lambda: monitor.reason,
                workdir=workdir,
            )
        outcome.ran = run.result.ran
        hits = [h for h in run.hits if h.path in entries_by_path]
        kept, dropped, catch_all = dh.filter_hits(
            hits, baselines, len(run_entries), site_hosts=(plan.host, plan.ip)
        )
        tool_run = tool_run_from(
            "ffuf",
            run.result,
            binary=ffuf.BINARY,
            version=ffuf_version,
            results_count=0 if catch_all else len(kept),
        )
        if run.stop_reason and tool_run.status in ("ok", "stopped"):
            # ffuf ended early (its own stop rule, or ours): say why in the run's own words.
            tool_run = replace(tool_run, status="stopped", skip_reason=run.stop_reason)
        tool_run = replace(
            tool_run,
            command=f"{tool_run.command}  # wordlist {wordlist.name} sha256 {wordlist.sha256}",
        )
        ffuf_record = _tool_record(scan, stats, tool_run)
        session.add(ffuf_record)

        if run.result.cancelled:
            # Keep what ran so far, then end the scan: nothing is left running.
            await session.commit()
            raise ScanCancelled(run.result.cancelled_by or "unknown")
        if not run.result.ran:
            _degrade(scan, log, "Directory brute force did not run: ffuf is not installed.")
            stats.not_run_hosts += 1
            return outcome
        if tool_run.status == "failed":
            first = next((ln for ln in run.result.stderr.splitlines() if ln.strip()), "")
            _degrade(
                scan,
                log,
                f"ffuf failed on {host} (exit code {run.result.returncode}): {first[:200]}".rstrip(
                    ": "
                ),
            )
        if run.stop_reason:
            outcome.stopped = True
            outcome.backpressured = bool(monitor.stopped) or "429" in run.stop_reason
            log.add(
                STAGE,
                f"{host}: stopped: {run.stop_reason}; the paths found so far are kept.",
                level="warn",
            )
            _degrade(
                scan,
                log,
                f"Directory brute force on {host} stopped early ({run.stop_reason}); "
                "its results are partial.",
            )
        await session.flush()

    rows: list[_Row] = []
    if catch_all:
        log.add(
            STAGE,
            f"{host}: answers almost every path ({len(kept)} left after filtering), so it is "
            "treated as a catch-all and no paths are recorded.",
            level="warn",
        )
        kept = []

    # --- 6/7: signatures, re-checked through the HTTP engine ------------------
    for hit in kept:
        entry = entries_by_path[hit.path]
        rows.append(
            _Row(
                entry=entry,
                method="GET",
                status=hit.status,
                length=hit.length,
                words=hit.words,
                lines=hit.lines,
                content_type=hit.content_type or None,
                redirect=hit.redirect or None,
            )
        )
    new_findings: list[tuple[_Row, PassiveCandidate | None]] = []
    for row in rows:
        probe = probe_for_path(row.entry.path)
        if probe is None or probe.method != "GET" or row.status != 200:
            continue
        if row.entry.path.lower().endswith(TEMPLATE_SUFFIXES):
            row.note = (
                "Looks like a template file, so it is not reported as a finding. Open it to "
                "check that it holds no real values."
            )
            continue
        await cancel.raise_if_cancelled()
        candidate = await _check_signature(
            probe, row, origin=origin, fetch=fetch, baselines=baseline_gets
        )
        new_findings.append((row, candidate))

    # --- 8: archives and dumps: HEAD only, never fetched by ffuf --------------
    head_rows: list[_Row] = []
    head_record: ToolRunRecord | None = None
    if head_entries and not outcome.backpressured:
        head_rows, head_candidates, head_record, head_stopped = await _head_pass(
            plan=plan,
            entries=head_entries,
            fetch=fetch,
            base_head=base_head,
            cancel=cancel,
            log=log,
            scan=scan,
            stats=stats,
            budget_left=budget_left,
        )
        new_findings.extend(head_candidates)
        if head_stopped:
            outcome.stopped = True
            outcome.backpressured = True
            _degrade(
                scan,
                log,
                f"The archive check on {host} stopped early (the host pushed back); "
                "its results are partial.",
            )
        if head_record is not None:
            session.add(head_record)
            await session.flush()
    rows.extend(head_rows)

    # Verify twice and build the findings.
    for row, candidate in new_findings:
        if candidate is None:
            continue
        await cancel.raise_if_cancelled()
        assert candidate.reproduce is not None
        outcome_check = await verify_candidate(candidate.reproduce)
        if not outcome_check.passed:
            row.verdict = "not_confirmed"
            row.note = (
                f"The file signature matched once but reproduced only "
                f"{outcome_check.reproduced_count} of {outcome_check.attempted_count} times, "
                "so it is not reported as a finding."
            )
            continue
        finding = build_finding(scan=scan, candidate=candidate, outcome=outcome_check)
        row.finding = finding
        row.verdict = "confirmed"
        row.rule_id = candidate.rule_id
        row.note = None
        stats.confirmed += 1
        stats.confirmed_fingerprints.add(candidate_fingerprint(candidate))
        log.add(
            STAGE,
            f"Finding [{candidate.severity}, confirmed]: {candidate.title}",
            level="warn" if candidate.severity in ("critical", "high") else "info",
        )
        for ref in candidate.evidence:
            transcripts.setdefault(
                ref.transcript_id,
                TranscriptRecord(
                    transcript_id=ref.transcript_id,
                    scan_id=scan.id,
                    persona_id=None,
                    method=ref.method,
                    url=ref.url[:2000],
                    status_code=ref.status_code,
                ),
            )

    # --- 9: crawl seeds ------------------------------------------------------
    _pick_crawl_seeds(rows, plan=plan, scope_guard=scope_guard, stats=stats)

    # --- persist this host ----------------------------------------------------
    rows.sort(key=lambda r: r.sort_key)
    if len(rows) > MAX_ROWS_PER_HOST:
        log.add(
            STAGE,
            f"{host}: {len(rows)} paths found; the first {MAX_ROWS_PER_HOST} are recorded.",
            level="warn",
        )
        rows = rows[:MAX_ROWS_PER_HOST]
    # Transcript rows first: Evidence.transcript_id is a real foreign key to them.
    session.add_all([t for t in transcripts.values() if t not in session])
    await session.flush()
    session.add_all([r.finding for r in rows if r.finding is not None])
    await session.flush()
    for row in rows:
        session.add(
            _discovered_path(
                scan,
                plan,
                row,
                wordlist=wordlist.name,
                tool_run_id=head_record.id
                if row.from_head_pass and head_record
                else (ffuf_record.id if ffuf_record else None),
            )
        )
    stats.hits += len(rows)
    ignored = sum(dropped.values())
    confirmed_here = sum(1 for r in rows if r.verdict == "confirmed")
    log.add(
        STAGE,
        f"{host}: {len(rows)} path(s) found, {confirmed_here} confirmed, {ignored} ignored as "
        "catch-all/baseline.",
    )
    return outcome


async def _check_signature(
    probe: Probe,
    row: _Row,
    *,
    origin: str,
    fetch: _EngineFetch,
    baselines: list[EngineResponse],
) -> PassiveCandidate | None:
    """Fetch a hit through the engine and decide whether its content has the
    file's signature. Sets the row's note when it does not; returns the
    candidate (with its re-check thunk) when it does."""
    url = f"{origin}/{row.entry.path}"
    response = await fetch(probe.method, url, withhold_body=probe.withhold)
    if response is None:
        row.verdict = "not_confirmed"
        row.note = f"Could not be fetched again to check its content ({fetch.last_error})."
        return None
    if response.status_code != 200:
        row.verdict = "not_confirmed"
        row.note = f"Answered {response.status_code} when fetched again to check its content."
        return None
    if probe.method == "GET" and any(matches_baseline(probe, response, b) for b in baselines):
        row.verdict = "not_confirmed"
        row.note = "Answers exactly like a made-up path, so its content proves nothing."
        return None
    matched = probe.validate(response)
    if matched is None:
        row.verdict = "not_confirmed"
        row.note = "Answered 200 but the content does not look like the file it is named after."
        return None
    return build_candidate(probe, origin, url, response, matched, fetch)


async def _head_pass(
    *,
    plan: HostPlan,
    entries: list[wordlists.Entry],
    fetch: _EngineFetch,
    base_head: EngineResponse | None,
    cancel: _Cancel,
    log: Log,
    scan: Scan,
    stats: DirStats,
    budget_left: Callable[[], float],
) -> tuple[list[_Row], list[tuple[_Row, PassiveCandidate | None]], ToolRunRecord | None, bool]:
    """HEAD every archive/dump name through the guarded engine. Returns the
    rows (only answers that look like a download), the candidates still to be
    re-checked, the tool-run record, and whether the host pushed back."""
    started = datetime.now(UTC)
    monitor = dh.BackpressureMonitor()
    lines: list[str] = []
    rows: list[_Row] = []
    candidates: list[tuple[_Row, PassiveCandidate | None]] = []
    sent = 0
    skipped_scope = 0
    cut_by_budget = False
    for entry in entries:
        await cancel.raise_if_cancelled()
        if budget_left() <= 0:
            cut_by_budget = True
            break
        probe = probe_for_path(entry.path)
        if probe is None or probe.method != "HEAD":
            continue
        url = f"{plan.origin}/{entry.path}"
        before = fetch.out_of_scope
        response = await fetch("HEAD", url)
        if response is None:
            if fetch.out_of_scope > before:
                skipped_scope += 1
                lines.append(f"HEAD {url} -> skipped (outside the scan's scope)")
            else:
                lines.append(f"HEAD {url} -> no answer ({fetch.last_error})")
            continue
        sent += 1
        ctype = _header(response.headers, "content-type") or ""
        length = _header(response.headers, "content-length") or ""
        lines.append(f"HEAD {url} -> {response.status_code} {ctype} {length}".rstrip())
        if not monitor.observe(response.status_code):
            break
        if response.status_code != 200 or matches_baseline(probe, response, base_head):
            continue
        matched = probe.validate(response)
        if matched is None:
            continue
        row = _Row(
            entry=entry,
            method="HEAD",
            status=response.status_code,
            length=int(length) if length.isdigit() else None,
            words=None,
            lines=None,
            content_type=ctype or None,
            redirect=None,
            from_head_pass=True,
        )
        rows.append(row)
        candidates.append((row, build_candidate(probe, plan.origin, url, response, matched, fetch)))
    if cut_by_budget:
        log.add(STAGE, f"{plan.host}: the archive check stopped: time budget.", level="warn")
    stopped = monitor.stopped
    run = ToolRun(
        tool=HEAD_TOOL,
        status="stopped" if stopped else "ok",
        command=(
            f"HEAD {len(entries)} archive/dump path(s) on {plan.origin} through the guarded "
            f"HTTP engine ({sent} sent, {skipped_scope} skipped by scope rules)"
        ),
        started_at=started,
        finished_at=datetime.now(UTC),
        exit_code=None if stopped else 0,
        stdout="\n".join(lines),
        results_count=len(rows),
        skip_reason=monitor.reason if stopped else None,
    )
    return rows, candidates, _tool_record(scan, stats, run), stopped


def _pick_crawl_seeds(
    rows: list[_Row], *, plan: HostPlan, scope_guard: ScopeGuard, stats: DirStats
) -> None:
    """Mark up to MAX_CRAWL_SEEDS pages (over the whole step) the crawl should
    also start from: answers that are HTML pages, or redirects within the same
    site, that are not file-signature or secret paths."""
    destructive = DestructiveActionGuard()
    for row in rows:
        if len(stats.path_seeds) >= MAX_CRAWL_SEEDS:
            return
        if row.verdict != "found" or row.method != "GET":
            continue
        if probe_for_path(row.entry.path) is not None:
            continue
        html = row.status == 200 and "text/html" in (row.content_type or "").lower()
        same_site_redirect = False
        if row.status in (301, 302) and row.redirect:
            target = dh.normalise_redirect(
                row.redirect, f"{plan.origin}/{row.entry.path}", (plan.host, plan.ip)
            )
            # a same-site target is reduced to its path; another host keeps "//host/path"
            same_site_redirect = (
                target is not None and target.startswith("/") and not target.startswith("//")
            )
        if not (html or same_site_redirect):
            continue
        url = f"{plan.origin}/{row.entry.path}"
        if not scope_guard.evaluate(method="GET", url=url).allowed:
            continue
        if destructive.check(method="GET", url=url).is_suspect:
            continue
        if url in stats.path_seeds:
            continue
        stats.path_seeds.append(url)
        row.crawl_seed = True


def _discovered_path(
    scan: Scan,
    plan: HostPlan,
    row: _Row,
    *,
    wordlist: str,
    tool_run_id: uuid.UUID | None,
) -> DiscoveredPath:
    path = "/" + row.entry.path
    note = row.note
    return DiscoveredPath(
        scan_id=scan.id,
        tool_run_id=tool_run_id,
        origin=plan.origin[:300],
        path=path[:1000],
        url=f"{plan.origin}{path}"[:2000],
        method=row.method,
        status_code=row.status,
        content_length=row.length,
        words=row.words,
        lines=row.lines,
        content_type=row.content_type[:200] if row.content_type else None,
        redirect_location=redact_url(row.redirect)[:2000] if row.redirect else None,
        category=row.entry.category[:20],
        wordlist=wordlist[:50],
        verdict=row.verdict,
        rule_id=row.rule_id,
        finding_id=row.finding.id if row.finding is not None else None,
        note=note[:500] if note else None,
        crawl_seed=row.crawl_seed,
    )


__all__ = [
    "DirStats",
    "HostPlan",
    "allowed_paths",
    "host_order",
    "run_dir_bruteforce",
    "select_hosts",
]
