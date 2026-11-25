"""naabu wrapper (MIT, projectdiscovery/naabu): TCP port discovery. It opens
connections to the target's ports, so it only runs for scans the user has
explicitly authorised (see the worker's active-tools gate) and only ever with
the argument list ``build_args`` returns.

What naabu is deliberately *not* allowed to do here, and why:

- connect scan only (``-scan-type c``): no SYN scan, no raw packets, no UDP, so
  it needs no privileges and no libpcap, and behaves like any client;
- ``-Pn`` (no host discovery): no ICMP/ARP/TCP pings beyond the port probes;
- ``-rate`` is ALWAYS given. naabu's own default is 1000 packets per second,
  far above anything this tool should do to a client's server, and ``-rate 0``
  is a fatal error, so the value is clamped to at least 1;
- ``-retries`` is 2 for top-1000 and 1 for all ports (naabu defaults to 3 full
  passes), which bounds the total number of probes: the time estimate in
  sentinel_core.scan_options and the timeout below rely on it;
- ``-verify`` re-checks each open port with a second TCP connection, and
  ``-exclude-cdn`` limits CDN/WAF addresses to ports 80 and 443 (scanning a
  shared edge network is neither useful nor polite);
- ``-duc`` stops the update check (no calls home), ``-nc`` no colour codes;
- each run gets a private HOME / XDG_CONFIG_HOME / cwd, because naabu writes
  ``~/.config/naabu`` and ``~/.config/uncover``.

Known naabu v2.7.0 facts this relies on (verified against the real binary):
JSON lines look like ``{"host"?, "ip", "timestamp", "port", "protocol": "tcp",
"tls": false}`` (``host`` only when the input was a hostname; ``cdn`` and
``cdn-name`` when ``-cdn`` found one); ``-iv`` takes 4 or 6; a connect scan as
non-root prints "Running CONNECT scan with non root privileges"; naabu does
NOT refuse private addresses (the caller does that, with
sentinel_core.address_guard) and it can report false "open" ports behind a
transparent proxy or a firewall that completes every handshake, hence the
``suspicious`` flag on the result.
"""

from __future__ import annotations

import ipaddress
import json
import re
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import structlog
from sentinel_core.scan_options import ALL_PORTS_COUNT, TOP_PORTS_COUNT

from .tooling import STOPPED_BY_CALLER, ToolRunResult, run_tool, tool_available

log = structlog.get_logger(__name__)

BINARY = "naabu"

# More open ports than this on ONE address is not a real server, it is a
# firewall or proxy answering for everything.
SUSPICIOUS_OPEN_PORTS = 100
SUSPICIOUS_NOTE = "ports appear open everywhere (firewall/proxy?)"

# Safety net on memory and on a runaway run: a scan that reports more open
# ports than this is stopped (the result is already flagged suspicious).
MAX_OPEN_PORTS = 1000
TOO_MANY_PORTS = f"stopped: more than {MAX_OPEN_PORTS} open ports on one address"

# Whole-run timeout when the caller gives none: 1.5 x the estimate + 60 s.
# The estimate is the one sentinel_core.scan_options.estimate() shows the
# person: top ports = ports x 2 passes / pps, all ports = ports x 1 pass / pps,
# plus a few seconds for start-up and the -verify pass.
FIXED_SECONDS = 5
TIMEOUT_FACTOR = 1.5
TIMEOUT_SLACK_S = 60

_VERSION_RE = re.compile(r"(?:Current Version:\s*)?v?(\d+\.\d+\.\d+)")
_FATAL_RE = re.compile(r"\[FTL\]\s*(.+)")


def _packets_per_second(pps: float) -> int:
    """naabu's ``-rate``: a positive integer (``-rate 0`` is fatal)."""
    return max(1, int(pps))


def estimate_seconds(*, all_ports: bool, pps: float) -> float:
    """Expected duration of one address, mirroring scan_options.estimate()."""
    rate = _packets_per_second(pps)
    if all_ports:
        return ALL_PORTS_COUNT / rate + FIXED_SECONDS
    return TOP_PORTS_COUNT * 2 / rate + FIXED_SECONDS


def default_timeout_s(*, all_ports: bool, pps: float) -> float:
    return TIMEOUT_FACTOR * estimate_seconds(all_ports=all_ports, pps=pps) + TIMEOUT_SLACK_S


async def is_available() -> bool:
    """naabu is on PATH."""
    return tool_available(BINARY)


async def version() -> str | None:
    """The naabu version as "v2.7.0" (it prints "Current Version: 2.7.0"), or
    None when it is missing or does not answer. Never raises."""
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-naabu-") as tmp:
            result = await run_tool(
                BINARY,
                ["-version", "-duc", "-nc"],
                timeout_s=5.0,
                env={"HOME": tmp, "XDG_CONFIG_HOME": f"{tmp}/cfg"},
                cwd=tmp,
            )
    except Exception:  # noqa: BLE001 — a version string is never worth a failed scan
        return None
    if not result.ran or result.timed_out:
        return None
    match = _VERSION_RE.search(result.stderr + result.stdout)
    return f"v{match.group(1)}" if match else None


def _checked_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The address as an object, or ValueError. Besides catching typos this
    keeps anything that is not an address (such as a value starting with "-")
    out of the argument list."""
    return ipaddress.ip_address(ip.strip())


def build_args(ip: str, *, all_ports: bool, pps: float) -> list[str]:
    """The complete naabu argument list. Golden-tested: do not add flags
    without changing the tests and the reasoning in this module's docstring.

    ``ip`` is a literal IP address (never a hostname: the caller has already
    resolved and checked it). ``pps`` is packets per second; the caller picks
    it from the scan's speed and, for all ports, never above
    scan_options.ALL_PORTS_MAX_PPS. Raises ValueError for a non-address."""
    address = _checked_ip(ip)
    return [
        "-host", str(address),
        *(["-p", "1-65535"] if all_ports else ["-top-ports", str(TOP_PORTS_COUNT)]),
        "-scan-type", "c", "-Pn",
        "-rate", str(_packets_per_second(pps)),
        "-retries", "1" if all_ports else "2",
        "-exclude-cdn", "-cdn", "-verify",
        "-iv", "6" if address.version == 6 else "4",
        "-json", "-duc", "-nc", "-v",
    ]  # fmt: skip


@dataclass(frozen=True, slots=True)
class OpenPort:
    ip: str
    port: int
    protocol: str = "tcp"
    host: str | None = None  # the input name, when naabu was given a hostname
    tls: bool = False
    cdn: bool = False
    cdn_name: str | None = None


def _port_number(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int) and 1 <= value <= 65535:
        return value
    return None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def parse_line(line: str) -> OpenPort | None:
    """One ``-json`` stdout line to an open port. Banner, ``[INF]``/``[DBG]``
    log lines, blank lines, non-JSON, JSON that is not an object, and objects
    without a usable ip and port all give None; other missing keys take their
    defaults and unknown keys are ignored. Never raises."""
    try:
        line = line.strip()
        if not line.startswith("{"):
            return None
        doc = json.loads(line)
        if not isinstance(doc, dict):
            return None
        ip = _text(doc.get("ip"))
        port = _port_number(doc.get("port"))
        if ip is None or port is None:
            return None
        cdn_name = _text(doc.get("cdn-name"))
        return OpenPort(
            ip=ip,
            port=port,
            protocol=_text(doc.get("protocol")) or "tcp",
            host=_text(doc.get("host")),
            tls=doc.get("tls") is True,
            cdn=doc.get("cdn") is True or cdn_name is not None,
            cdn_name=cdn_name,
        )
    except (ValueError, RecursionError):
        return None


@dataclass(slots=True)
class NaabuRun:
    result: ToolRunResult
    ports: list[OpenPort] = field(default_factory=list)
    # Why the run ended early, in words for the activity log: "cancelled",
    # "timed out" or the stop reason. None when naabu finished (or never ran).
    stop_reason: str | None = None
    # More than SUSPICIOUS_OPEN_PORTS ports open on one address.
    suspicious: bool = False
    # naabu exited non-zero on its own (not killed by us); its fatal message
    # when it printed one. None otherwise.
    error: str | None = None

    @property
    def note(self) -> str | None:
        """A line for the activity log / tool run when the results need a caveat."""
        return SUSPICIOUS_NOTE if self.suspicious else None


async def run_naabu(
    ip: str,
    *,
    all_ports: bool,
    pps: float,
    timeout_s: float | None = None,
    cancel_check: Callable[[], Awaitable[str | None]] | None = None,
    on_port: Callable[[OpenPort], None] | None = None,
) -> NaabuRun:
    """Scans one address and collects its open ports.

    - Ports are parsed as they stream in; ``on_port`` is called once for each
      new (ip, port, protocol). It cannot stop the scan, and an exception in it
      is logged and ignored.
    - ``timeout_s`` defaults to 1.5 x the estimate + 60 s. On a timeout the
      ports found so far are kept.
    - ``cancel_check`` is polled about once a second (see tooling.run_tool).
    - naabu's HOME, XDG_CONFIG_HOME and cwd are a private directory, removed
      afterwards. Timeout, cancel, stop and any exception (CancelledError
      included) kill naabu's whole process group before this returns or raises.
    - A binary that is not installed gives ``result.ran == False`` (not raised).
    - Raises ValueError if ``ip`` is not an IP address.
    """
    args = build_args(ip, all_ports=all_ports, pps=pps)
    if timeout_s is None:
        timeout_s = default_timeout_s(all_ports=all_ports, pps=pps)

    ports: list[OpenPort] = []
    seen: set[tuple[str, int, str]] = set()
    over_limit = False

    def on_line(line: str) -> bool:
        nonlocal over_limit
        found = parse_line(line)
        if found is None:
            return True
        key = (found.ip, found.port, found.protocol)
        if key in seen:
            return True
        seen.add(key)
        ports.append(found)
        if on_port is not None:
            try:
                on_port(found)
            except Exception:  # noqa: BLE001 — a progress callback must not end the scan
                log.warning("naabu.on_port_failed", exc_info=True)
        if len(ports) > MAX_OPEN_PORTS:
            over_limit = True
            return False
        return True

    with tempfile.TemporaryDirectory(prefix="sentinel-naabu-") as tmp:
        result = await run_tool(
            BINARY,
            args,
            timeout_s=timeout_s,
            on_stdout_line=on_line,
            cancel_check=cancel_check,
            env={"HOME": tmp, "XDG_CONFIG_HOME": f"{tmp}/cfg"},
            cwd=tmp,
        )
    return NaabuRun(
        result=result,
        ports=ports,
        stop_reason=_stop_reason(result, over_limit),
        suspicious=len(ports) > SUSPICIOUS_OPEN_PORTS,
        error=_error(result),
    )


def _stop_reason(result: ToolRunResult, over_limit: bool) -> str | None:
    if not result.ran:
        return None
    if result.cancelled:
        return "cancelled"
    if result.timed_out:
        return "timed out"
    if result.stopped_reason is not None:
        if over_limit:
            return TOO_MANY_PORTS
        # A callback that raised is reported by run_tool in its own words.
        return result.stopped_reason if result.stopped_reason != STOPPED_BY_CALLER else None
    return None


def _error(result: ToolRunResult) -> str | None:
    """Set only when naabu itself failed: exit code non-zero and not killed by
    us (a killed run has returncode None)."""
    if not result.ran or result.returncode in (None, 0):
        return None
    fatal = _FATAL_RE.search(result.stderr) or _FATAL_RE.search(result.stdout)
    message = f"naabu exited with code {result.returncode}"
    return f"{message}: {fatal.group(1).strip()[:300]}" if fatal else message
