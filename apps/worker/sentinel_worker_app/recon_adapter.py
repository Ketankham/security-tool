"""Maps sentinel_recon results onto the scan: DB rows (Asset, ToolRunRecord),
activity-log lines, the scope check recon uses, and the extra start pages
the logged-out crawl gets from live discovered hosts."""

from __future__ import annotations

import uuid

from sentinel_core.redact import redact_text
from sentinel_core.scope_guard import ScopeGuard
from sentinel_db.models import Asset, ToolRunRecord
from sentinel_db.models.tool_run import MAX_STDERR_CHARS, MAX_STDOUT_CHARS
from sentinel_recon import ReconResult, ToolRun

from .scan_log import NullScanLog, ScanLog

# Live subdomains the logged-out crawl also starts from. Each costs crawl
# budget (pages are shared across start points), so only a handful.
MAX_EXTRA_CRAWL_HOSTS = 5


def host_check_for(scope_guard: ScopeGuard):
    """Recon sends one GET / per host, so a host is probe-able only if that
    exact request would pass the guard: host rules, and path rules on "/"
    (an include rule like /app/ means "/" itself is out of scope)."""

    def check(host: str) -> str | None:
        decision = scope_guard.evaluate(method="GET", url=f"https://{host}/")
        return None if decision.allowed else decision.reason

    return check


def _cap(text: str, limit: int) -> tuple[str, bool]:
    text = redact_text(text)
    return (text[:limit], True) if len(text) > limit else (text, False)


def tool_run_records(
    scan_id: uuid.UUID, runs: list[ToolRun], *, phase: str, start_seq: int = 1
) -> list[ToolRunRecord]:
    records = []
    for i, run in enumerate(runs):
        stdout, stdout_cut = _cap(run.stdout, MAX_STDOUT_CHARS)
        stderr, stderr_cut = _cap(run.stderr, MAX_STDERR_CHARS)
        records.append(
            ToolRunRecord(
                scan_id=scan_id,
                seq=start_seq + i,
                phase=phase,
                tool=run.tool[:50],
                binary=run.binary,
                version=run.version,
                command=redact_text(run.command)[:4000],
                status=run.status,
                skip_reason=(run.skip_reason or None) and run.skip_reason[:500],
                started_at=run.started_at,
                finished_at=run.finished_at,
                duration_ms=run.duration_ms,
                exit_code=run.exit_code,
                timed_out=run.timed_out,
                results_count=run.results_count,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_cut,
                stderr_truncated=stderr_cut,
            )
        )
    return records


def asset_rows(scan_id: uuid.UUID, result: ReconResult) -> list[Asset]:
    return [
        Asset(
            scan_id=scan_id,
            host=a.host,
            ip_addresses=a.ips,
            http_probes=[
                {
                    "url": p.url,
                    "status_code": p.status_code,
                    "title": p.title,
                    "server": p.server,
                    "tech": p.tech,
                    "error": p.error,
                    "cdn": p.cdn,
                    "content_type": p.content_type,
                }
                for p in a.http_probes
            ],
            tech_fingerprint=a.tech,
            discovery_source=a.source[:30],
            sources=a.sources,
            scope_status=a.scope_status,
            scope_reason=(a.scope_reason or None) and a.scope_reason[:500],
        )
        for a in result.assets
    ]


def _describe_run(run: ToolRun) -> str:
    name = f"{run.tool} {run.version}" if run.version else run.tool
    if run.status in ("skipped", "not_installed"):
        return f"{name}: not run — {run.skip_reason or run.status}."
    took = f" in {run.duration_ms / 1000:.1f}s" if run.duration_ms is not None else ""
    code = f", exit code {run.exit_code}" if run.exit_code is not None else ""
    return (
        f"{name}: {run.status.replace('_', ' ')}{took}{code}, {run.results_count} result(s). "
        f"Command: {run.command}"
    )


def log_recon(scan_log: ScanLog | NullScanLog, result: ReconResult) -> None:
    for run in result.tool_runs:
        scan_log.add(
            "recon",
            _describe_run(run),
            level="info" if run.status in ("ok", "skipped") else "warn",
            tool=run.tool,
            status=run.status,
        )
    for asset in result.assets:
        if asset.scope_status != "in_scope":
            scan_log.add(
                "recon",
                f"Host {asset.host}: not probed ({asset.scope_status.replace('_', ' ')}). "
                f"{asset.scope_reason or ''}".strip(),
            )
            continue
        probes = "; ".join(
            f"{p.url} -> {p.status_code if p.status_code is not None else p.error}"
            + (f' "{p.title}"' if p.title else "")
            for p in asset.http_probes[:3]
        )
        tech = f"; tech: {', '.join(asset.tech)}" if asset.tech else ""
        scan_log.add(
            "recon",
            f"Host {asset.host} (sources: {', '.join(asset.sources) or asset.source}); IPs: "
            f"{', '.join(asset.ips) or 'none'}; {'live' if asset.live else 'not answering'}"
            f"{': ' + probes if probes else ''}{tech}",
        )
    for note in result.notes:
        scan_log.add("recon", note, level="warn")


def extra_crawl_seeds(
    result: ReconResult, *, root_domain: str, scope_guard: ScopeGuard
) -> list[str]:
    """Start pages on live discovered subdomains (not the root or www, which
    the crawl starts from anyway), in scope, at most MAX_EXTRA_CRAWL_HOSTS."""
    skip = {root_domain.lower(), f"www.{root_domain.lower()}"}
    seeds: list[str] = []
    for asset in result.live_assets:
        if asset.host in skip:
            continue
        probe = next((p for p in asset.http_probes if p.status_code is not None), None)
        if probe is None or not probe.url:
            continue
        url = probe.url if probe.url.count("/") > 2 else probe.url + "/"
        if scope_guard.evaluate(method="GET", url=url).allowed:
            seeds.append(url)
        if len(seeds) >= MAX_EXTRA_CRAWL_HOSTS:
            break
    return seeds
