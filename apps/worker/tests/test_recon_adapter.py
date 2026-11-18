import uuid

from sentinel_core.scope_guard import ScopeGuard, ScopeRule
from sentinel_recon import DiscoveredAsset, HttpProbeResult, ReconResult, ToolRun
from sentinel_worker_app import recon_adapter


def _guard(rules=None):
    return ScopeGuard(
        allowed_hosts={"acme.test", "*.acme.test"},
        rules=rules or [],
        target_ownership_verified=True,
    )


def _live(host: str, url: str | None = None) -> DiscoveredAsset:
    return DiscoveredAsset(
        host=host,
        source="subfinder",
        ips=["93.184.216.34"],
        http_probes=[
            HttpProbeResult(url=url or f"https://{host}", status_code=200, title=None, server=None)
        ],
    )


def _result(assets) -> ReconResult:
    return ReconResult(
        root_domain="acme.test", assets=assets, tool_availability={}, wildcard_dns_suspected=False
    )


def test_host_check_uses_host_and_root_path_rules():
    check = recon_adapter.host_check_for(
        _guard([ScopeRule(kind="host", pattern="admin.acme.test", effect="exclude")])
    )
    assert check("api.acme.test") is None
    assert "exclude" in (check("admin.acme.test") or "")
    assert check("evil.example") is not None
    # With path include rules only /app/ is in scope, so GET / is not.
    only_app = recon_adapter.host_check_for(
        _guard([ScopeRule(kind="path_prefix", pattern="/app/", effect="include")])
    )
    assert only_app("api.acme.test") is not None


def test_extra_crawl_seeds_skip_root_www_dead_and_out_of_scope_and_cap():
    assets = [
        _live("acme.test"),
        _live("www.acme.test"),
        DiscoveredAsset(host="dead.acme.test", source="subfinder", ips=["93.184.216.34"]),
        DiscoveredAsset(host="int.acme.test", source="subfinder", scope_status="private_ip"),
        _live("admin.acme.test"),
        *[_live(f"h{i}.acme.test") for i in range(8)],
    ]
    seeds = recon_adapter.extra_crawl_seeds(
        _result(assets),
        root_domain="acme.test",
        scope_guard=_guard([ScopeRule(kind="host", pattern="admin.acme.test", effect="exclude")]),
    )
    assert seeds == [f"https://h{i}.acme.test/" for i in range(5)]


def test_tool_run_records_redact_and_cap():
    huge = "x" * 600_000
    runs = [
        ToolRun(tool="httpx", status="ok", command="pd-httpx -json", stdout=huge, stderr="ok"),
        ToolRun(tool="subfinder", status="skipped", skip_reason="not installed"),
    ]
    scan_id = uuid.uuid4()
    records = recon_adapter.tool_run_records(scan_id, runs, phase="recon")
    assert [r.seq for r in records] == [1, 2]
    assert records[0].stdout_truncated is True and len(records[0].stdout) == 512_000
    assert records[0].stderr_truncated is False
    assert records[1].skip_reason == "not installed"


def test_log_recon_describes_runs_hosts_and_notes():
    class Log:
        def __init__(self):
            self.lines = []

        def add(self, stage, message, **kwargs):
            self.lines.append((stage, message, kwargs.get("level", "info")))

    result = ReconResult(
        root_domain="acme.test",
        assets=[
            _live("acme.test"),
            DiscoveredAsset(
                host="int.acme.test",
                source="subfinder",
                scope_status="private_ip",
                scope_reason="Resolves to 10.0.0.5",
            ),
        ],
        tool_availability={},
        wildcard_dns_suspected=False,
        notes=["a note"],
        tool_runs=[ToolRun(tool="httpx", status="timed_out", command="pd-httpx", version="v1")],
    )
    log = Log()
    recon_adapter.log_recon(log, result)
    text = "\n".join(m for _, m, _ in log.lines)
    assert "httpx v1: timed out" in text
    assert "int.acme.test: not probed (private ip)" in text
    assert "acme.test" in text and "live" in text
    assert ("recon", "a note", "warn") in log.lines
