"""Port scanning and service detection (naabu, then nmap), the worker side.

This is an *active* tool: it opens TCP connections to the ports of the client's
servers, so it only runs for a scan whose authorisation record covers
``port_scan`` (see active_tools.authorised_tools) and only ever does what is
written down here. The rules that keep it safe, each enforced in code and
covered by a test:

- an address is scanned only if it came from a recon host that is in scope and
  not excluded, and (unless private addresses are allowed for this deployment)
  only if it is a public address. That includes a public name that resolves to
  127.0.0.1, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, ::1 or a
  multicast address: such an address is refused and counted, never scanned;
- connect scans only: no SYN, no UDP, no OS detection (the wrappers build the
  argument lists and are golden-tested; this module cannot add flags);
- a rate is always given, from the scan's speed, and scanning all 65,535 ports
  never goes faster than ALL_PORTS_MAX_PPS;
- all ports needs both opt-ins (the scan's option AND the authorisation's
  separate all-ports confirmation) and only the first ALL_PORTS_MAX_IPS addresses
  get it; the rest get the top 1,000 ports;
- one address at a time, a time budget for the whole step, and a cancel check
  between addresses and (through ``cancel_check``) inside each tool;
- nmap (service/version detection and default safe scripts) runs only on the
  Full profile, only when installed, only on the ports naabu found open, and
  not on an address with more than 50 open ports or one that looks like a
  proxy answering for everything;
- everything nmap printed is redacted before it is stored, whatever the wrapper
  already did (script output, product and version strings, the -oN report).
"""

from __future__ import annotations

import ipaddress
import shlex
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Protocol

from sentinel_core import scan_options
from sentinel_core.address_guard import non_public_ips
from sentinel_core.redact import redact_text
from sentinel_core.scope_guard import ScopeGuard
from sentinel_db.models import PortService, Scan, ToolRunRecord
from sentinel_recon import ReconResult, ToolRun, naabu_wrapper, nmap_wrapper, port_guess
from sentinel_recon.runs import skipped_run, tool_run_from
from sentinel_recon.tooling import ToolRunResult
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import recon_adapter
from .cancel import ScanCancelled
from .scan_log import NullScanLog, ScanLog

STAGE = "ports"

# Do not start a tool with less time than this left in the budget.
MIN_RUN_SECONDS = 10
# nmap needs at least this long to be worth starting (service probes take a while).
MIN_NMAP_SECONDS = 30
NMAP_MISSING_NOTE = "nmap not installed — services named from port numbers (unverified)"
MAX_HOSTS_STORED_PER_IP = 50
MAX_PORTS_IN_LOG = 30
MAX_HOSTS_IN_LOG = 5
# How many nmap-detected web services on unusual ports become crawl start pages.
MAX_WEB_SEEDS = 5

_STANDARD_WEB_PORTS = frozenset({80, 443})

Log = ScanLog | NullScanLog
Clock = Callable[[], float]


class _Cancel(Protocol):
    """What this step needs from a cancel.CancelWatch."""

    async def requested(self) -> str | None: ...

    async def raise_if_cancelled(self) -> None: ...


@dataclass(slots=True)
class PortTools:
    """The external tools, injectable so tests can use fakes. The defaults are
    the real wrappers."""

    naabu: Callable[..., Awaitable[naabu_wrapper.NaabuRun]] = naabu_wrapper.run_naabu
    nmap: Callable[..., Awaitable[nmap_wrapper.NmapRun]] = nmap_wrapper.run_nmap
    naabu_available: Callable[[], Awaitable[bool]] = naabu_wrapper.is_available
    nmap_available: Callable[[], Awaitable[bool]] = nmap_wrapper.is_available
    naabu_version: Callable[[], Awaitable[str | None]] = naabu_wrapper.version
    nmap_version: Callable[[], Awaitable[str | None]] = nmap_wrapper.version


@dataclass(slots=True)
class PortStats:
    """What the step did. ``as_dict`` is the RECON phase's "ports" stats."""

    ips_planned: int = 0
    ips_scanned: int = 0
    open_ports: int = 0
    all_ports_ips: int = 0
    # ran | not_installed | skipped (Light profile, too many ports, a proxy-like host)
    nmap: str = "skipped"
    # addresses not scanned: over the cap, or out of time
    not_scanned: int = 0
    # addresses refused because they are not public (and private is not allowed)
    refused_ips: int = 0
    suspicious_ips: int = 0
    # Where the next ToolRunRecord.seq starts.
    next_seq: int = 1
    # Web services nmap detected on non-standard ports: crawl start pages
    # (candidates only; the caller re-checks scope and the address guard).
    web_seeds: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ips_planned": self.ips_planned,
            "ips_scanned": self.ips_scanned,
            "open_ports": self.open_ports,
            "all_ports_ips": self.all_ports_ips,
            "nmap": self.nmap,
            "not_scanned": self.not_scanned,
            "refused_ips": self.refused_ips,
            "suspicious_ips": self.suspicious_ips,
        }


# --- Choosing addresses ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IpPlan:
    ip: str
    hosts: tuple[str, ...]  # in-scope host names that resolved to it, root first


@dataclass(slots=True)
class IpSelection:
    ips: list[IpPlan]  # to scan, in order, within the cap
    over_cap: list[IpPlan]  # eligible but beyond the cap
    refused: list[str]  # one line per refused address / host, for the log
    refused_ips: int  # distinct addresses refused as non-public


def host_order(root: str, hosts: list[str]) -> list[str]:
    """The root domain first, then the rest A to Z."""
    root = root.lower()
    first = [root] if root in hosts else []
    return first + sorted(h for h in hosts if h not in first)


def select_ips(
    recon_result: ReconResult,
    *,
    scope_guard: ScopeGuard,
    allow_private: bool,
    max_ips: int,
) -> IpSelection:
    """The addresses this step may scan.

    Only addresses of recon hosts that are in scope (``scope_status ==
    "in_scope"``, whether or not the host answered HTTP) and that the scope
    guard still allows. A non-public address (loopback, RFC 1918, link-local,
    CGNAT, multicast, ...) is refused unless ``allow_private``, even when a
    public host name resolved to it. Duplicates are merged, so an address shared
    by several hosts is scanned once and remembers all of them. The root
    domain's addresses come first, then the hosts A to Z."""
    by_host = {
        a.host.lower(): a
        for a in recon_result.assets
        if a.scope_status == "in_scope"  # excluded, unresolved, private, capped: never
    }
    hosts_of: dict[str, list[str]] = {}
    refused: list[str] = []
    refused_addresses: set[str] = set()
    for host in host_order(recon_result.root_domain, list(by_host)):
        decision = scope_guard.evaluate(method="GET", url=f"https://{host}/")
        if not decision.allowed:
            refused.append(f"{host}: {decision.reason}")
            continue
        for raw in by_host[host].ips:
            try:
                address = ipaddress.ip_address((raw or "").strip().split("%", 1)[0])
            except ValueError:
                refused.append(f"{host}: {raw!r} is not an IP address")
                continue
            ip = str(address)
            if non_public_ips([ip]) and not allow_private:
                refused_addresses.add(ip)
                refused.append(
                    f"{host}: {ip} is a non-public address; scans do not connect to internal "
                    "addresses"
                )
                continue
            names = hosts_of.setdefault(ip, [])
            if host not in names:
                names.append(host)
    plans = [IpPlan(ip=ip, hosts=tuple(names)) for ip, names in hosts_of.items()]
    return IpSelection(
        ips=plans[:max_ips],
        over_cap=plans[max_ips:],
        refused=refused,
        refused_ips=len(refused_addresses),
    )


# --- The step -------------------------------------------------------------------


def _degrade(scan: Scan, log: Log, message: str) -> None:
    log.add(STAGE, message, level="warn")
    scan.is_degraded = True
    scan.degraded_reasons = [*scan.degraded_reasons, message]


def _tool_record(
    scan: Scan, stats: PortStats, run: ToolRun, session: AsyncSession
) -> ToolRunRecord:
    (record,) = recon_adapter.tool_run_records(
        scan.id, [run], phase="recon", start_seq=stats.next_seq
    )
    record.id = uuid.uuid4()
    stats.next_seq += 1
    session.add(record)
    return record


def _names(hosts: tuple[str, ...]) -> str:
    shown = ", ".join(hosts[:MAX_HOSTS_IN_LOG])
    return shown + (" …" if len(hosts) > MAX_HOSTS_IN_LOG else "")


def _port_list(ports: list[int]) -> str:
    shown = ", ".join(str(p) for p in ports[:MAX_PORTS_IN_LOG])
    return shown + (
        f" … (+{len(ports) - MAX_PORTS_IN_LOG} more)" if len(ports) > MAX_PORTS_IN_LOG else ""
    )


def _clip(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    return redact_text(value)[:limit] or None


async def run_ports(
    session: AsyncSession,
    scan: Scan,
    target,
    recon_result: ReconResult,
    scope_guard: ScopeGuard,
    profile: str,
    speed_pps: float,
    cancel: _Cancel,
    log: Log,
    seq: int,
    *,
    authorised_by: str = "unknown",
    all_ports_authorised: bool = False,
    environment: str = "production",
    allow_private: bool = False,
    budget_s: float | None = None,
    max_ips: int | None = None,
    all_ports_max_ips: int | None = None,
    tools: PortTools | None = None,
    clock: Clock = time.monotonic,
) -> PortStats:
    """Runs the step for ``scan`` and returns what it did. ``seq`` is the next
    free ToolRunRecord.seq. Rows and tool runs are committed after each
    address, so a crash or a cancel keeps what was already found.

    ``speed_pps`` is the scan speed's packets per second
    (scan_options.PORT_PACKETS_PER_SECOND). ``all_ports_authorised`` is the
    authorisation record's separate all-ports confirmation; all ports also needs
    the scan's own ``all_ports`` option and the Full profile. ``environment``
    ("production" or "staging") picks nmap's script set.

    Raises ScanCancelled (from ``cancel``) when the scan is cancelled."""
    stats = PortStats(next_seq=seq)
    tools = tools or PortTools()
    profile = "full" if profile == "full" else "light"
    full = profile == "full"
    nmap_environment: nmap_wrapper.Environment = (
        "staging" if environment == "staging" else "production"
    )
    cap_ips = max_ips if max_ips is not None else scan_options.PORT_MAX_IPS[profile]
    cap_all = all_ports_max_ips if all_ports_max_ips is not None else scan_options.ALL_PORTS_MAX_IPS
    # Never faster than the fastest speed setting, whatever the caller passed.
    pps = max(1, min(int(speed_pps), max(scan_options.PORT_PACKETS_PER_SECOND.values())))
    all_pps = min(pps, scan_options.ALL_PORTS_MAX_PPS)

    all_ports_wanted = scan.options.get("all_ports") is True if scan.options else False
    all_ports_on = all_ports_wanted and all_ports_authorised and full
    if all_ports_wanted and not all_ports_on:
        why = (
            "the Full recon profile is needed"
            if not full
            else "its separate confirmation is not on the authorisation record"
        )
        log.add(
            STAGE,
            f"All 65,535 ports was requested but {why}; the top 1,000 ports are scanned instead.",
            level="warn",
        )

    budget = float(
        budget_s
        if budget_s is not None
        else scan_options.PORT_BUDGET_S[profile]
        + (scan_options.ALL_PORTS_EXTRA_BUDGET_S if all_ports_on else 0)
    )

    # --- which addresses -------------------------------------------------------
    selection = select_ips(
        recon_result, scope_guard=scope_guard, allow_private=allow_private, max_ips=cap_ips
    )
    for line in selection.refused:
        log.add(STAGE, f"Not scanned: {line}.", level="warn")
    stats.refused_ips = selection.refused_ips
    if selection.over_cap:
        stats.not_scanned += len(selection.over_cap)
        listed = ", ".join(p.ip for p in selection.over_cap)
        log.add(
            STAGE,
            f"{len(selection.over_cap)} address(es) not scanned: over the limit of {cap_ips} "
            f"per scan ({listed}).",
            level="warn",
        )
    plans = selection.ips
    stats.ips_planned = len(plans)
    if not plans:
        log.add(STAGE, "Port scan: no in-scope public address to scan.", level="warn")
        await session.commit()
        return stats

    # --- naabu installed? ------------------------------------------------------
    if not await tools.naabu_available():
        _tool_record(
            scan,
            stats,
            tool_run_from(
                "naabu",
                ToolRunResult(ran=False, command=naabu_wrapper.BINARY),
                binary=naabu_wrapper.BINARY,
                version=None,
                results_count=0,
            ),
            session,
        )
        stats.not_scanned += len(plans)
        _degrade(scan, log, "Port scan did not run: naabu is not installed on the worker.")
        await session.commit()
        return stats

    nmap_installed = full and await tools.nmap_available()
    all_ips = {p.ip for p in plans[:cap_all]} if all_ports_on else set()
    all_note = (
        f"; all 65,535 ports on {', '.join(p.ip for p in plans[:cap_all])} "
        f"(at most {all_pps} packets/s)"
        if all_ips
        else ""
    )
    log.add(
        STAGE,
        f"Port scan of {len(plans)} IP(s): top 1,000 TCP ports, connect scan, {pps} packets/s, "
        f"one IP at a time{all_note}. Authorised by {authorised_by}.",
    )
    if all_ips and len(plans) > len(all_ips):
        rest = [p.ip for p in plans if p.ip not in all_ips]
        log.add(
            STAGE,
            f"All 65,535 ports applies to the first {cap_all} address(es) only; the top 1,000 "
            f"ports are scanned on {', '.join(rest)}.",
        )
    if not full:
        log.add(
            STAGE,
            "Light recon profile: service names come from port numbers and are unverified; the "
            "Full profile detects services with nmap when it is installed.",
        )
    elif not nmap_installed:
        log.add(STAGE, NMAP_MISSING_NOTE, level="warn")
        _tool_record(scan, stats, skipped_run("nmap", NMAP_MISSING_NOTE), session)
        stats.nmap = "not_installed"

    naabu_version = await tools.naabu_version()
    nmap_version = await tools.nmap_version() if nmap_installed else None
    started = clock()

    for index, plan in enumerate(plans):
        await cancel.raise_if_cancelled()
        remaining = budget - (clock() - started)
        if remaining < MIN_RUN_SECONDS:
            left = plans[index:]
            stats.not_scanned += len(left)
            listed = ", ".join(p.ip for p in left)
            log.add(STAGE, f"Not scanned: {listed} (time budget).", level="warn")
            _degrade(
                scan,
                log,
                f"Port scan ran out of time (budget {budget / 60:g} min); not scanned: {listed}.",
            )
            break

        await _scan_ip(
            session=session,
            scan=scan,
            plan=plan,
            all_ports=plan.ip in all_ips,
            pps=all_pps if plan.ip in all_ips else pps,
            full=full,
            nmap_installed=nmap_installed,
            nmap_environment=nmap_environment,
            tools=tools,
            cancel=cancel,
            log=log,
            stats=stats,
            budget_left=lambda: budget - (clock() - started),
            naabu_version=naabu_version,
            nmap_version=nmap_version,
        )
        await session.commit()

    await session.commit()
    return stats


async def _scan_ip(
    *,
    session: AsyncSession,
    scan: Scan,
    plan: IpPlan,
    all_ports: bool,
    pps: int,
    full: bool,
    nmap_installed: bool,
    nmap_environment: nmap_wrapper.Environment,
    tools: PortTools,
    cancel: _Cancel,
    log: Log,
    stats: PortStats,
    budget_left: Callable[[], float],
    naabu_version: str | None,
    nmap_version: str | None,
) -> None:
    ip = plan.ip
    where = f"{ip} ({_names(plan.hosts)})"
    existing = {
        (r.port, r.protocol): r
        for r in (
            await session.execute(
                select(PortService).where(PortService.scan_id == scan.id, PortService.ip == ip)
            )
        )
        .scalars()
        .all()
    }

    # --- naabu ----------------------------------------------------------------
    args = naabu_wrapper.build_args(ip, all_ports=all_ports, pps=pps)
    log.add(
        STAGE,
        f"Running: {shlex.join([naabu_wrapper.BINARY, *args])}"
        + (" (all 65,535 ports)" if all_ports else ""),
    )
    timeout = max(
        float(MIN_RUN_SECONDS),
        min(naabu_wrapper.default_timeout_s(all_ports=all_ports, pps=pps), budget_left()),
    )
    run = await tools.naabu(
        ip,
        all_ports=all_ports,
        pps=pps,
        timeout_s=timeout,
        cancel_check=cancel.requested,
    )
    ports = [p for p in run.ports if p.ip == ip and p.protocol == "tcp"]
    tool_run = tool_run_from(
        "naabu",
        run.result,
        binary=naabu_wrapper.BINARY,
        version=naabu_version,
        results_count=len(ports),
    )
    if run.stop_reason and tool_run.status == "ok":
        tool_run = replace(tool_run, status="stopped", skip_reason=run.stop_reason)
    elif run.suspicious and tool_run.status == "ok":
        tool_run = replace(tool_run, skip_reason=naabu_wrapper.SUSPICIOUS_NOTE)
    naabu_record = _tool_record(scan, stats, tool_run, session)
    await session.flush()  # the rows below point at it

    # Keep what was found even when the run was cut short.
    for found in ports:
        _upsert_open_port(session, scan, plan, found, existing, naabu_record.id, stats)

    if run.result.cancelled:
        await session.commit()
        raise ScanCancelled(run.result.cancelled_by or "unknown")
    if not run.result.ran:
        stats.not_scanned += 1
        _degrade(scan, log, f"Port scan of {ip} did not run: naabu is not installed.")
        return
    stats.ips_scanned += 1
    if all_ports:
        stats.all_ports_ips += 1

    if tool_run.status == "failed" or run.error:
        _degrade(
            scan,
            log,
            f"naabu failed on {where}: {run.error or 'it exited with an error'}; "
            "the next address continues.",
        )
    elif tool_run.status == "timed_out" or run.stop_reason:
        _degrade(
            scan,
            log,
            f"The port scan of {where} stopped early ({run.stop_reason or 'timed out'}); "
            "its results are partial.",
        )

    open_numbers = sorted({p.port for p in ports})
    if open_numbers:
        log.add(STAGE, f"{where}: {len(open_numbers)} open: {_port_list(open_numbers)}")
    else:
        log.add(STAGE, f"{where}: no open ports")

    if run.suspicious:
        stats.suspicious_ips += 1
        _degrade(
            scan,
            log,
            f"{where}: {len(open_numbers)} ports are open, so {naabu_wrapper.SUSPICIOUS_NOTE} "
            "Its ports are listed but may not be real, and nmap was not run on them.",
        )

    # --- nmap -----------------------------------------------------------------
    if not full or not open_numbers or run.suspicious or run.result.cancelled:
        return
    if not nmap_installed:
        return  # noted once, at the start
    if len(open_numbers) > nmap_wrapper.MAX_PORTS:
        reason = nmap_wrapper.SKIPPED_TOO_MANY_PORTS
        _tool_record(scan, stats, skipped_run("nmap", f"{ip}: {reason}"), session)
        log.add(STAGE, f"{where}: nmap {reason}.", level="warn")
        if stats.nmap != "ran":
            stats.nmap = "skipped"
        return
    remaining = budget_left()
    if remaining < MIN_NMAP_SECONDS:
        reason = "skipped: not enough time left in the budget"
        _tool_record(scan, stats, skipped_run("nmap", f"{ip}: {reason}"), session)
        log.add(STAGE, f"{where}: nmap {reason}.", level="warn")
        if stats.nmap != "ran":
            stats.nmap = "skipped"
        return
    await cancel.raise_if_cancelled()
    await _run_nmap(
        session=session,
        scan=scan,
        plan=plan,
        where=where,
        numbers=open_numbers,
        pps=pps,
        environment=nmap_environment,
        timeout=min(nmap_wrapper.DEFAULT_TIMEOUT_S, remaining),
        existing=existing,
        tools=tools,
        cancel=cancel,
        log=log,
        stats=stats,
        nmap_version=nmap_version,
    )


def _upsert_open_port(
    session: AsyncSession,
    scan: Scan,
    plan: IpPlan,
    found: naabu_wrapper.OpenPort,
    existing: dict[tuple[int, str], PortService],
    tool_run_id: uuid.UUID,
    stats: PortStats,
) -> None:
    """A port naabu found open: a row named from the port number (unverified)."""
    key = (found.port, found.protocol)
    row = existing.get(key)
    cdn = (found.cdn_name or "cdn")[:100] if found.cdn else None
    if row is None:
        row = PortService(
            scan_id=scan.id,
            ip=plan.ip,
            hosts=list(plan.hosts[:MAX_HOSTS_STORED_PER_IP]),
            port=found.port,
            protocol=found.protocol[:10],
            scripts={},
        )
        session.add(row)
        existing[key] = row
        stats.open_ports += 1
    row.tool_run_id = tool_run_id
    row.state = "open"
    row.service = port_guess.guess(found.port)
    row.product = row.version = row.extra_info = None
    row.confidence = port_guess.CONFIDENCE
    row.found_by = "naabu"
    row.cdn = cdn


async def _run_nmap(
    *,
    session: AsyncSession,
    scan: Scan,
    plan: IpPlan,
    where: str,
    numbers: list[int],
    pps: int,
    environment: nmap_wrapper.Environment,
    timeout: float,
    existing: dict[tuple[int, str], PortService],
    tools: PortTools,
    cancel: _Cancel,
    log: Log,
    stats: PortStats,
    nmap_version: str | None,
) -> None:
    ip = plan.ip
    log.add(
        STAGE,
        f"Running: nmap service detection ({environment} scripts) on {len(numbers)} open port(s) "
        f"of {ip}: -sT -sV -p {','.join(map(str, numbers))}",
    )
    run = await tools.nmap(
        ip,
        numbers,
        environment=environment,
        pps=pps,
        timeout_s=timeout,
        cancel_check=cancel.requested,
    )
    if run.skipped:
        _tool_record(scan, stats, skipped_run("nmap", f"{ip}: {run.skipped_reason}"), session)
        log.add(STAGE, f"{where}: nmap {run.skipped_reason}.", level="warn")
        if stats.nmap != "ran":
            stats.nmap = "skipped"
        return
    tool_run = tool_run_from(
        "nmap",
        run.result,
        binary=nmap_wrapper.BINARY,
        version=nmap_version,
        results_count=sum(1 for s in run.services if s.state == "open"),
    )
    if run.stop_reason and tool_run.status in ("ok", "stopped"):
        tool_run = replace(tool_run, status="stopped", skip_reason=run.stop_reason)
    if run.failed and tool_run.status == "ok":
        tool_run = replace(tool_run, status="failed", skip_reason=(run.parse_error or "")[:500])
    # What nmap printed besides the XML: kept, redacted and capped, as a second output.
    tool_run = replace(
        tool_run,
        extra_output=run.normal_output,
        extra_output_label="nmap normal output (-oN)" if run.normal_output else None,
    )
    record = _tool_record(scan, stats, tool_run, session)
    await session.flush()  # the rows below point at it
    if run.result.cancelled:
        _merge_services(session, scan, plan, run.services, existing, record.id, stats)
        await session.commit()
        raise ScanCancelled(run.result.cancelled_by or "unknown")
    if not run.result.ran:
        if stats.nmap != "ran":
            stats.nmap = "not_installed"
        log.add(STAGE, NMAP_MISSING_NOTE, level="warn")
        return
    stats.nmap = "ran"
    detected = _merge_services(session, scan, plan, run.services, existing, record.id, stats)

    if tool_run.status == "failed" or run.parse_error:
        _degrade(
            scan,
            log,
            f"nmap could not be read for {where} "
            f"({(run.parse_error or 'it exited with an error')[:200]}); "
            "services there are named from port numbers (unverified).",
        )
    elif run.stop_reason:
        _degrade(
            scan,
            log,
            f"nmap on {where} stopped early ({run.stop_reason}); its results are partial.",
        )
    summary = ", ".join(detected[:MAX_PORTS_IN_LOG])
    log.add(
        STAGE,
        f"{where}: nmap identified {len(detected)} of {len(numbers)} service(s)"
        + (f": {summary}" if summary else "")
        + ".",
    )


def _service_label(info: nmap_wrapper.ServiceInfo) -> str:
    name = " ".join(x for x in (info.product, info.version) if x) or info.service or "unknown"
    return f"{info.port}/{name}"


def _merge_services(
    session: AsyncSession,
    scan: Scan,
    plan: IpPlan,
    services: list[nmap_wrapper.ServiceInfo],
    existing: dict[tuple[int, str], PortService],
    tool_run_id: uuid.UUID,
    stats: PortStats,
) -> list[str]:
    """Merges nmap's answers into the rows naabu made. Returns a label for each
    service nmap actually identified (probed, not just named from the port table).

    - open: the row takes nmap's service, product, version, extra info and script
      output, ``confidence`` "detected" and ``found_by`` "nmap". When nmap only
      guessed from its own port table (method "table"), the name is still a guess,
      so the row stays "port_guess" (but keeps the scripts and found_by "nmap");
    - closed / filtered / anything else: only the state changes. Rows are never deleted."""
    detected: list[str] = []
    for info in services:
        if info.protocol != "tcp":
            continue
        key = (info.port, info.protocol)
        row = existing.get(key)
        if info.state != "open":
            if row is not None:
                row.state = info.state[:20]
            continue
        if row is None:
            row = PortService(
                scan_id=scan.id,
                ip=plan.ip,
                hosts=list(plan.hosts[:MAX_HOSTS_STORED_PER_IP]),
                port=info.port,
                protocol=info.protocol[:10],
                scripts={},
                service=port_guess.guess(info.port),
                confidence=port_guess.CONFIDENCE,
            )
            session.add(row)
            existing[key] = row
            stats.open_ports += 1
        row.tool_run_id = tool_run_id
        row.state = "open"
        row.found_by = "nmap"
        row.scripts = {s.id[:100]: redact_text(s.output) for s in info.scripts}
        table_guess = info.method == "table"
        name = _clip(info.service, 100)
        if table_guess:
            if name and name != "unknown":
                row.service = name
            row.confidence = port_guess.CONFIDENCE
        else:
            row.service = name or row.service
            row.confidence = "detected"
            detected.append(_service_label(info))
        row.product = _clip(info.product, 200)
        row.version = _clip(info.version, 100)
        row.extra_info = _clip(info.extra_info, 300)
        if not table_guess:
            _maybe_web_seed(stats, plan, info)
    return detected


def _maybe_web_seed(stats: PortStats, plan: IpPlan, info: nmap_wrapper.ServiceInfo) -> None:
    """A web service nmap found on a port other than 80/443 is a start page for
    the crawl: http(s)://<host>:<port>/, https when it runs inside TLS."""
    name = (info.service or "").lower()
    if not name.startswith("http") or info.port in _STANDARD_WEB_PORTS or not plan.hosts:
        return
    if len(stats.web_seeds) >= MAX_WEB_SEEDS:
        return
    secure = info.tunnel == "ssl" or name.startswith("https")
    host = plan.hosts[0]
    shown = f"[{host}]" if ":" in host else host
    url = f"{'https' if secure else 'http'}://{shown}:{info.port}/"
    if url not in stats.web_seeds:
        stats.web_seeds.append(url)


__all__ = [
    "IpPlan",
    "IpSelection",
    "PortStats",
    "PortTools",
    "host_order",
    "run_ports",
    "select_ips",
]
