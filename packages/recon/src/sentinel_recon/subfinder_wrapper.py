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

_NO_KEY_RE = re.compile(r"Cannot use the (\S+) source because there was no API key")
_SOURCE_ERR_RE = re.compile(r"Could not run source (\S+?):? ")


async def is_available() -> bool:
    return await looks_like_projectdiscovery_tool(BINARY)


def build_args(root_domain: str) -> list[str]:
    return [
        "-d", root_domain,
        "-json", "-cs",  # one JSON line per host, with the sources that reported it
        "-v", "-nc", "-duc",
        "-max-time", str(MAX_TIME_MINUTES),
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


async def run_subfinder(root_domain: str, *, timeout_s: float = 150.0) -> SubfinderOutcome:
    version = await tool_version(BINARY)
    result = await run_tool(BINARY, build_args(root_domain), timeout_s=timeout_s)
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


async def enumerate_subdomains(root_domain: str, *, timeout_s: float = 150.0) -> list[str]:
    """Host names only; [] (not an error) if subfinder isn't installed."""
    return sorted((await run_subfinder(root_domain, timeout_s=timeout_s)).hosts)
