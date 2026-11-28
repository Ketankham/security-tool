"""nmap wrapper: service and version detection on the ports naabu found open.

LICENCE EXCEPTION (read before changing anything here)
------------------------------------------------------
nmap is NOT MIT/permissive: it is under the Nmap Public Source License (NPSL),
which ADR-0002 does not permit by default. It is installed in the worker image
under a written, recorded exception (docs/adr/0002-build-vs-adopt-open-source.md,
"Exceptions"; infra/tools-manifest.json, entry "nmap"): approved by the project
owner on 2026-11-28 for INTERNAL use in the hosted worker, including our own
team testing clients' applications. No legal review was obtained.

The conditions that keep the exception small (do not widen them here):

- Full recon profile only (the Light profile never calls this module);
- the hosted worker only: nmap is never bundled into, or distributed with,
  anything we ship to a client, and clients do not log into Sentinel;
- reached only through this module, so it stays swappable for another
  service-detection tool without touching the worker;
- it runs as a separate process, never linked.

Re-examine the exception (OEM licence, legal opinion, or drop nmap) BEFORE
clients are given access to Sentinel or Sentinel is distributed or sold.

If the binary is missing (``is_available()`` is False, e.g. a local test
machine), the ports step reports naabu-only results with service names guessed
from port numbers (sentinel_recon.port_guess), marked unverified.

What nmap is deliberately *not* allowed to do here, and why:

- connect scan only (``-sT``, ``--unprivileged``): no SYN scan (``-sS``), no UDP
  (``-sU``), no OS detection (``-O``), no raw packets, no ``-sC`` shortcut;
- ``-Pn -n``: no host discovery and no DNS lookups (the caller passes an IP it
  has already resolved and checked);
- only the ports naabu found open (``-p``), at most MAX_PORTS of them, with
  ``--max-rate`` always set, and ``--host-timeout`` / ``--script-timeout``
  bounding how long one address can take;
- scripts are a boolean expression, never a list of names. Production uses
  ``default and safe and not http-*``: the http-* scripts request paths and
  methods of their own choosing, which would bypass this scan's scope rules
  (web ports are already covered by httpx and the crawler). Staging uses
  ``default``. Script output is capped and passed through redact_text because
  scripts such as ssh-hostkey or banner can print secrets the server reveals.
"""

from __future__ import annotations

import ipaddress
import re
import tempfile
import xml.etree.ElementTree as ET  # noqa: S405 — output of our own nmap run; DTDs/entities are refused below
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from sentinel_core.redact import redact_text

from .tooling import ToolRunResult, run_tool, tool_available

BINARY = "nmap"

Environment = Literal["production", "staging"]

# Skip nmap when one address has more open ports than this: such an address is
# almost certainly a firewall/proxy answering everything, and a script scan of
# that many ports would take far longer than its budget.
MAX_PORTS = 50
SKIPPED_TOO_MANY_PORTS = f"skipped: more than {MAX_PORTS} open ports"
SKIPPED_NO_PORTS = "skipped: no open ports to examine"

PRODUCTION_SCRIPTS = "default and safe and not http-*"
STAGING_SCRIPTS = "default"

DEFAULT_TIMEOUT_S = 1000.0

# Script output kept per script, and the -oN text kept per run.
MAX_SCRIPT_OUTPUT_CHARS = 4000
MAX_NORMAL_OUTPUT_BYTES = 512 * 1024

# Column sizes of the port_services table: parsed values are cut to fit.
_MAX_NAME, _MAX_PRODUCT, _MAX_VERSION, _MAX_EXTRA = 100, 200, 100, 300

_VERSION_RE = re.compile(r"Nmap version (\S+)")


async def is_available() -> bool:
    """nmap is on PATH. False in the production worker image (see the licence
    note above); callers fall back to naabu-only results."""
    return tool_available(BINARY)


async def version() -> str | None:
    """The version token of "Nmap version 7.93 ( https://nmap.org )", i.e.
    "7.93". None when nmap is missing or does not answer. Never raises."""
    try:
        result = await run_tool(BINARY, ["--version"], timeout_s=5.0)
    except Exception:  # noqa: BLE001 — a version string is never worth a failed scan
        return None
    if not result.ran or result.timed_out:
        return None
    match = _VERSION_RE.search(result.stdout + result.stderr)
    return match.group(1) if match else None


def build_args(
    ip: str,
    ports: list[int],
    *,
    environment: Environment,
    pps: float,
    normal_out: str,
) -> list[str]:
    """The complete nmap argument list. Golden-tested: do not add flags
    without changing the tests and the reasoning in this module's docstring.

    XML goes to stdout (``-oX -``), the human-readable report to the file
    ``normal_out``. ``ip`` must be a literal address (ValueError otherwise, so
    it can never be read as an option); IPv6 adds ``-6``. ``ports`` must be a
    non-empty list of valid TCP ports (ValueError otherwise)."""
    address = ipaddress.ip_address(ip.strip())
    if not ports:
        raise ValueError("nmap needs at least one port")
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"not a TCP port: {port!r}")
    scripts = PRODUCTION_SCRIPTS if environment == "production" else STAGING_SCRIPTS
    return [
        *(["-6"] if address.version == 6 else []),
        "-sT", "-Pn", "-n", "--unprivileged", "-sV",
        "--script", scripts,
        "--script-timeout", "60s", "--host-timeout", "900s", "--max-retries", "2",
        "--max-rate", str(max(1, int(pps))),
        "--reason", "-p", ",".join(map(str, ports)),
        "-oX", "-", "-oN", normal_out,
        str(address),
    ]  # fmt: skip


# --- XML ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScriptOutput:
    id: str
    output: str  # redacted, at most MAX_SCRIPT_OUTPUT_CHARS characters


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    port: int
    protocol: str
    state: str  # open | closed | filtered | open|filtered | ...
    reason: str | None = None  # nmap's --reason for the state, e.g. "syn-ack", "conn-refused"
    service: str | None = None  # nmap's service name, e.g. "ssh"
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    # nmap's own confidence in the service match, 0 to 10; None when absent.
    confidence: int | None = None
    # "table" = guessed from the port number by nmap, "probed" = from a probe.
    method: str | None = None
    tunnel: str | None = None  # "ssl" when the service runs inside TLS
    cpes: tuple[str, ...] = ()
    scripts: tuple[ScriptOutput, ...] = ()


def _clip(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    value = redact_text(value.strip())
    return value[:limit] or None


def _cap_script_output(text: str) -> str:
    # Redact the whole output first, then cut: a token straddling the cut must
    # not survive as a recognisable prefix.
    text = redact_text(text)
    if len(text) <= MAX_SCRIPT_OUTPUT_CHARS:
        return text
    return text[: MAX_SCRIPT_OUTPUT_CHARS - 1] + "…"


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _service_from_port(port: ET.Element) -> ServiceInfo | None:
    number = _int(port.get("portid"))
    if number is None or not 1 <= number <= 65535:
        return None
    state_el = port.find("state")
    service_el = port.find("service")
    scripts = tuple(
        ScriptOutput(id=(s.get("id") or "")[:100], output=_cap_script_output(s.get("output") or ""))
        for s in port.findall("script")
        if s.get("id")
    )
    kwargs: dict[str, object] = {}
    if service_el is not None:
        kwargs = {
            "service": _clip(service_el.get("name"), _MAX_NAME),
            "product": _clip(service_el.get("product"), _MAX_PRODUCT),
            "version": _clip(service_el.get("version"), _MAX_VERSION),
            "extra_info": _clip(service_el.get("extrainfo"), _MAX_EXTRA),
            "confidence": _int(service_el.get("conf")),
            "method": _clip(service_el.get("method"), 20),
            "tunnel": _clip(service_el.get("tunnel"), 20),
            "cpes": tuple(
                c.text.strip()[:200] for c in service_el.findall("cpe") if c.text and c.text.strip()
            ),
        }
    return ServiceInfo(
        port=number,
        protocol=(port.get("protocol") or "tcp")[:10],
        state=((state_el.get("state") if state_el is not None else None) or "unknown")[:20],
        reason=_clip(state_el.get("reason") if state_el is not None else None, 50),
        scripts=scripts,
        **kwargs,  # type: ignore[arg-type]
    )


def parse_xml(xml_text: str) -> tuple[list[ServiceInfo], str | None]:
    """nmap ``-oX`` output to ``(services, error)``: one ServiceInfo per
    ``host/ports/port`` element, whatever its state (callers keep the open
    ones). Never raises.

    Defensive by design: empty, garbage or truncated XML (a run killed by a
    timeout leaves a cut-off document) returns what could be read up to the
    break, plus an error string; the ports that were complete before the cut
    are kept. XML that declares entities or a DOCTYPE with an internal subset
    is refused outright (nmap never writes one; a server's banner cannot add
    one because nmap escapes it)."""
    if not xml_text or not xml_text.strip():
        return [], "nmap produced no XML output"
    if "<!ENTITY" in xml_text:
        return [], "nmap XML refused: it declares entities"
    parser: ET.XMLPullParser = ET.XMLPullParser(events=("end",))
    error: str | None = None
    try:
        parser.feed(xml_text)
        parser.close()
    except ET.ParseError as exc:
        error = f"nmap XML could not be fully parsed: {exc}"
    except Exception as exc:  # noqa: BLE001 — never raise out of a parser
        error = f"nmap XML could not be parsed ({type(exc).__name__})"
    services: list[ServiceInfo] = []
    try:
        for event in parser.read_events():
            element: object = event[-1]
            if not isinstance(element, ET.Element) or element.tag != "port":
                continue
            info = _service_from_port(element)
            if info is not None:
                services.append(info)
    except Exception as exc:  # noqa: BLE001
        error = error or f"nmap XML could not be read ({type(exc).__name__})"
    if error is None and not services and "<nmaprun" not in xml_text:
        error = "nmap output was not nmap XML"
    return services, error


# --- Running --------------------------------------------------------------------


@dataclass(slots=True)
class NmapRun:
    # The tool run, with stdout (the XML) and stderr passed through redact_text
    # so it is safe to store. ``ran`` is False when nmap was not started: not
    # installed (``skipped_reason`` None) or skipped (``skipped_reason`` set).
    result: ToolRunResult
    services: list[ServiceInfo] = field(default_factory=list)
    # The human-readable ``-oN`` report, redacted, at most 512 KiB. "" if none.
    normal_output: str = ""
    stop_reason: str | None = None  # "cancelled" | "timed out" | None
    # Set when the XML was missing, cut off or invalid. Services found before
    # the break are still in ``services``.
    parse_error: str | None = None
    # Set when nmap was deliberately not run ("skipped: more than 50 open ports").
    skipped_reason: str | None = None

    @property
    def skipped(self) -> bool:
        return self.skipped_reason is not None

    @property
    def not_installed(self) -> bool:
        return not self.result.ran and self.skipped_reason is None

    @property
    def failed(self) -> bool:
        """nmap ran to its own end but exited non-zero or left unusable XML."""
        r = self.result
        if not r.ran or self.stop_reason is not None:
            return False
        return r.returncode != 0 or self.parse_error is not None


def _skipped(reason: str) -> NmapRun:
    return NmapRun(result=ToolRunResult(ran=False), skipped_reason=reason)


def _read_normal_output(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_NORMAL_OUTPUT_BYTES + 1)
    except OSError:
        return ""
    text = redact_text(raw.decode(errors="replace"))
    return text.encode()[:MAX_NORMAL_OUTPUT_BYTES].decode(errors="ignore")


async def run_nmap(
    ip: str,
    ports: list[int],
    *,
    environment: Environment,
    pps: float,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    cancel_check: Callable[[], Awaitable[str | None]] | None = None,
) -> NmapRun:
    """Runs service detection and default safe scripts on ``ports`` of ``ip``.

    - More than MAX_PORTS ports (or none) is not run: ``skipped_reason`` says
      why and ``result.ran`` is False.
    - Ports are de-duplicated and sorted; ValueError for an invalid address or port.
    - nmap's HOME, XDG_CONFIG_HOME and cwd are a private directory, which also
      holds the ``-oN`` report; it is removed afterwards.
    - Timeout and cancel kill nmap's whole process group and keep whatever XML
      it had written (parsed leniently, see parse_xml); so does an exception
      such as CancelledError (which is re-raised).
    - A binary that is not installed gives ``not_installed`` (not raised).
    """
    unique_ports = sorted(set(ports))
    if len(unique_ports) > MAX_PORTS:
        return _skipped(SKIPPED_TOO_MANY_PORTS)
    if not unique_ports:
        return _skipped(SKIPPED_NO_PORTS)

    with tempfile.TemporaryDirectory(prefix="sentinel-nmap-") as tmp:
        normal_path = Path(tmp) / "nmap-normal.txt"
        args = build_args(
            ip, unique_ports, environment=environment, pps=pps, normal_out=str(normal_path)
        )
        result = await run_tool(
            BINARY,
            args,
            timeout_s=timeout_s,
            cancel_check=cancel_check,
            env={"HOME": tmp, "XDG_CONFIG_HOME": f"{tmp}/cfg"},
            cwd=tmp,
        )
        if not result.ran:
            return NmapRun(result=result)
        normal_output = _read_normal_output(normal_path)

    services, parse_error = parse_xml(result.stdout)
    stop_reason = "cancelled" if result.cancelled else "timed out" if result.timed_out else None
    if stop_reason is not None and not result.stdout.strip():
        parse_error = None  # nothing to parse because we stopped it: stop_reason says it all
    safe = replace(result, stdout=redact_text(result.stdout), stderr=redact_text(result.stderr))
    return NmapRun(
        result=safe,
        services=services,
        normal_output=normal_output,
        stop_reason=stop_reason,
        parse_error=parse_error,
    )
