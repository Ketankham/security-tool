"""What the Run scan choices mean. Shared by the API (validation, display)
and the worker (enforcement), so both agree.

speed: requests per second to the target, for every request the scan makes
    (crawler and HTTP engine share one rate limiter per target). "gentle" is
    for small or fragile client sites; the limiter also backs off on its own
    when the site answers 429/503.
depth: how many pages each persona's crawl may visit.
recon_profile: how far recon goes. "light" (default, safe for client
    production) uses subfinder's default data sources and checks up to 50
    hosts. "full" asks every subfinder data source (slower, finds more) and
    checks up to 150 hosts. Deeper tools (ports, directories) will key off
    this too; each of those also needs its own explicit authorisation.
active tools (dir_bruteforce, port_scan, all_ports): off by default. They send
    traffic a passive scan does not (guessed paths, port probes), so each scan
    that uses one carries a signed-in user and a recorded "I'm authorised"
    confirmation (sentinel_core.authorisation). IMPLEMENTED_ACTIVE_TOOLS lists
    the ones this build can actually run; a request for any other is refused.
"""

from __future__ import annotations

from typing import Literal

Speed = Literal["gentle", "normal", "fast"]
Depth = Literal["quick", "standard", "deep"]
ReconProfile = Literal["light", "full"]
Wordlist = Literal["sentinel-core", "seclists-common"]
TargetEnvironment = Literal["production", "staging"]

REQUESTS_PER_SECOND: dict[str, float] = {"gentle": 2.0, "normal": 5.0, "fast": 10.0}
MAX_PAGES_PER_PERSONA: dict[str, int] = {"quick": 30, "standard": 100, "deep": 300}

DEFAULT_SPEED: Speed = "normal"
DEFAULT_DEPTH: Depth = "standard"
DEFAULT_RECON_PROFILE: ReconProfile = "light"
RECON_PROFILES: tuple[str, ...] = ("light", "full")


def resolve(options: dict | None) -> tuple[float, int]:
    """(requests per second, max pages per persona) for a scan's stored
    options; unknown or missing values fall back to the defaults."""
    options = options or {}
    rps = REQUESTS_PER_SECOND.get(str(options.get("speed")), REQUESTS_PER_SECOND[DEFAULT_SPEED])
    pages = MAX_PAGES_PER_PERSONA.get(
        str(options.get("depth")), MAX_PAGES_PER_PERSONA[DEFAULT_DEPTH]
    )
    return rps, pages


def resolve_recon_profile(options: dict | None) -> ReconProfile:
    """The scan's recon profile; scans created before profiles existed (and
    any unknown value) get the safe default, light."""
    value = str((options or {}).get("recon_profile"))
    return "full" if value == "full" else DEFAULT_RECON_PROFILE


# --- Active tools ---------------------------------------------------------------

ACTIVE_TOOL_KEYS: tuple[str, ...] = ("dir_bruteforce", "port_scan", "all_ports")
# The tools this build can actually run. A request for any other is refused by
# the API ("... is not available yet.") and skipped by the worker. Later
# releases add "dir_bruteforce", then "port_scan" and "all_ports".
IMPLEMENTED_ACTIVE_TOOLS: tuple[str, ...] = ()

ACTIVE_TOOL_LABELS: dict[str, str] = {
    "dir_bruteforce": "Directory brute force",
    "port_scan": "Port scanning",
    "all_ports": "All 65,535 ports",
}

DEFAULT_WORDLIST: Wordlist = "sentinel-core"
WORDLISTS: tuple[str, ...] = ("sentinel-core", "seclists-common")
TARGET_ENVIRONMENTS: tuple[str, ...] = ("production", "staging")

# Packets per second for port scans, by the scan's speed setting. Scanning
# every port never goes faster than ALL_PORTS_MAX_PPS whatever the speed.
PORT_PACKETS_PER_SECOND: dict[str, int] = {"gentle": 50, "normal": 100, "fast": 200}
ALL_PORTS_MAX_PPS = 100
TOP_PORTS_COUNT = 1000
ALL_PORTS_COUNT = 65535

# Wordlist sizes (entries). A test pins the real files to these ceilings.
WORDLIST_MAX_ENTRIES: dict[str, int] = {"sentinel-core": 1500, "seclists-common": 4751}

# Caps on how many hosts / IPs one scan works through, by recon profile.
DIR_MAX_HOSTS: dict[str, int] = {"light": 5, "full": 10}
PORT_MAX_IPS: dict[str, int] = {"light": 10, "full": 25}
ALL_PORTS_MAX_IPS = 3

# Wall-clock budgets in seconds; a step stops (and says so) when its budget is spent.
DIR_BUDGET_S: dict[str, int] = {"light": 1800, "full": 3600}
PORT_BUDGET_S: dict[str, int] = {"light": 1200, "full": 2700}
ALL_PORTS_EXTRA_BUDGET_S = 1800

_PORT_FIXED_SECONDS_PER_IP = 5


def active_tools(options: dict | None) -> list[str]:
    """The active tools a scan's stored options switched on, in a fixed order."""
    options = options or {}
    return [key for key in ACTIVE_TOOL_KEYS if options.get(key) is True]


def resolve_wordlist(options: dict | None) -> Wordlist:
    value = (options or {}).get("wordlist")
    return "seclists-common" if value == "seclists-common" else DEFAULT_WORDLIST


def resolve_target_environment(options: dict | None) -> TargetEnvironment:
    """Unknown or missing means production: the more conservative setting."""
    return "staging" if (options or {}).get("target_environment") == "staging" else "production"


def resolve_speed(options: dict | None) -> Speed:
    value = str((options or {}).get("speed"))
    if value == "gentle":
        return "gentle"
    if value == "fast":
        return "fast"
    return "normal" if value == "normal" else DEFAULT_SPEED


def estimate(options: dict | None) -> dict:
    """Worst-case time the active tools could take, per host / IP and in total
    (seconds), so the person sees the cost before they start. Computed from
    the same constants the worker enforces, so the numbers agree.

    Each tool's entry is None when it is switched off. ``total_seconds`` adds
    the tools that are on (they run one after another)."""
    options = options or {}
    profile = resolve_recon_profile(options)
    speed = resolve_speed(options)
    rps = REQUESTS_PER_SECOND[speed]
    pps = PORT_PACKETS_PER_SECOND[speed]
    wanted = set(active_tools(options))

    directory: dict | None = None
    if "dir_bruteforce" in wanted:
        wordlist = resolve_wordlist(options)
        entries = WORDLIST_MAX_ENTRIES[wordlist]
        budget = DIR_BUDGET_S[profile]
        hosts = DIR_MAX_HOSTS[profile]
        per_host = min(entries / rps, budget)
        directory = {
            "wordlist": wordlist,
            "entries": entries,
            "requests_per_second": rps,
            "max_hosts": hosts,
            "seconds_per_host": int(per_host),
            "seconds_total": int(min(hosts * per_host, budget)),
            "requests_total_max": entries * hosts,
            "budget_seconds": budget,
        }

    ports: dict | None = None
    if "port_scan" in wanted:
        budget = PORT_BUDGET_S[profile]
        ips = PORT_MAX_IPS[profile]
        per_ip = TOP_PORTS_COUNT * 2 / pps + _PORT_FIXED_SECONDS_PER_IP
        ports = {
            "ports_per_ip": TOP_PORTS_COUNT,
            "packets_per_second": pps,
            "max_ips": ips,
            "seconds_per_ip": int(per_ip),
            "seconds_total": int(min(ips * per_ip, budget)),
            "budget_seconds": budget,
        }

    all_ports: dict | None = None
    if "all_ports" in wanted:
        all_pps = min(pps, ALL_PORTS_MAX_PPS)
        per_ip = ALL_PORTS_COUNT / all_pps + _PORT_FIXED_SECONDS_PER_IP
        all_ports = {
            "ports_per_ip": ALL_PORTS_COUNT,
            "packets_per_second": all_pps,
            "max_ips": ALL_PORTS_MAX_IPS,
            "seconds_per_ip": int(per_ip),
            "seconds_total": int(min(ALL_PORTS_MAX_IPS * per_ip, ALL_PORTS_EXTRA_BUDGET_S)),
            "budget_seconds": ALL_PORTS_EXTRA_BUDGET_S,
        }

    total = sum(t["seconds_total"] for t in (directory, ports, all_ports) if t is not None)
    return {
        "recon_profile": profile,
        "speed": speed,
        "dir_bruteforce": directory,
        "port_scan": ports,
        "all_ports": all_ports,
        "total_seconds": total,
    }
