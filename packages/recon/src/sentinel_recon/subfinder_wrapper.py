"""subfinder wrapper (MIT, ProjectDiscovery — see ADR-0002). Passive
subdomain enumeration only, per docs/02 Phase 1: it asks public data
sources (certificate logs, DNS datasets) about the domain and never sends a
packet to the target itself, so the scan's speed limit does not apply here.

Runs with ``-v`` on purpose: the verbose log is what shows the tester which
sources were queried, which were skipped for lack of an API key and which
failed — "found 0" means nothing without that.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .models import ToolRun
from .runs import tool_run_from
from .tooling import looks_like_projectdiscovery_tool, run_tool, tool_version

BINARY = "subfinder"
# subfinder's own budget (minutes) — kept under our subprocess timeout so it
# stops cleanly and prints its summary instead of being killed.
MAX_TIME_MINUTES = 2
FULL_MAX_TIME_MINUTES = 5  # -all queries every source, which takes longer

_NO_KEY_RE = re.compile(r"Cannot use the (\S+) source because there was no API key")
_SOURCE_ERR_RE = re.compile(r"Could not run source (\S+?):? ")


async def is_available() -> bool:
    return await looks_like_projectdiscovery_tool(BINARY)


def build_args(root_domain: str, *, all_sources: bool = False) -> list[str]:
    return [
        "-d", root_domain,
        "-json", "-cs",  # one JSON line per host, with the sources that reported it
        *(["-all"] if all_sources else []),
        "-v", "-nc", "-duc",
        "-max-time", str(FULL_MAX_TIME_MINUTES if all_sources else MAX_TIME_MINUTES),
        "-timeout", "20",
    ]  # fmt: skip


@dataclass
class SubfinderOutcome:
    hosts: dict[str, list[str]]  # host -> sources that reported it
    run: ToolRun
    sources_without_key: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)


def parse_hosts(stdout: str, root_domain: str) -> dict[str, list[str]]:
    hosts: dict[str, set[str]] = {}
    root = root_domain.lower().rstrip(".")
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue
        host = str(doc.get("host") or "").lower().rstrip(".")
        # Data sources sometimes return junk ("*.acme.com", other domains).
        if not host or "*" in host or not (host == root or host.endswith("." + root)):
            continue
        sources = doc.get("sources")
        if sources is None and doc.get("source"):
            sources = [doc["source"]]
        hosts.setdefault(host, set()).update(str(s) for s in (sources or []))
    return {h: sorted(s) for h, s in sorted(hosts.items())}


async def run_subfinder(
    root_domain: str, *, all_sources: bool = False, timeout_s: float | None = None
) -> SubfinderOutcome:
    # Our kill timer sits above subfinder's own -max-time so it normally stops
    # cleanly and prints its summary.
    if timeout_s is None:
        timeout_s = (FULL_MAX_TIME_MINUTES if all_sources else MAX_TIME_MINUTES) * 60 + 30
    version = await tool_version(BINARY)
    result = await run_tool(
        BINARY, build_args(root_domain, all_sources=all_sources), timeout_s=timeout_s
    )
    hosts = parse_hosts(result.stdout, root_domain) if result.ran else {}
    run = tool_run_from(
        "subfinder", result, binary=BINARY, version=version, results_count=len(hosts)
    )
    return SubfinderOutcome(
        hosts=hosts,
        run=run,
        sources_without_key=sorted(set(_NO_KEY_RE.findall(result.stderr))),
        sources_failed=sorted(set(_SOURCE_ERR_RE.findall(result.stderr))),
    )


async def enumerate_subdomains(root_domain: str, *, timeout_s: float | None = None) -> list[str]:
    """Host names only; [] (not an error) if subfinder isn't installed."""
    return sorted((await run_subfinder(root_domain, timeout_s=timeout_s)).hosts)
