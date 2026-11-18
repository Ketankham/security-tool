from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from sentinel_recon.models import HttpProbeResult, ToolRun
from sentinel_recon.phase import MAX_CANDIDATE_HOSTS, run_recon
from sentinel_recon.subfinder_wrapper import SubfinderOutcome


def _patches(
    stack: ExitStack,
    *,
    subfinder: bool = False,
    httpx_bin: bool = False,
    found: dict[str, list[str]] | None = None,
    wildcard: bool = False,
    resolve=None,
    probes: list[HttpProbeResult] | None = None,
    no_key: list[str] | None = None,
) -> AsyncMock:
    p = "sentinel_recon.phase."
    stack.enter_context(
        patch(p + "subfinder_wrapper.is_available", new=AsyncMock(return_value=subfinder))
    )
    stack.enter_context(patch(p + "http_probe.is_available", new=AsyncMock(return_value=httpx_bin)))
    stack.enter_context(patch(p + "tlsx_wrapper.is_available", new=AsyncMock(return_value=False)))
    stack.enter_context(patch(p + "detect_wildcard_dns", new=AsyncMock(return_value=wildcard)))
    stack.enter_context(
        patch(
            p + "subfinder_wrapper.run_subfinder",
            new=AsyncMock(
                return_value=SubfinderOutcome(
                    hosts=found or {},
                    run=ToolRun(tool="subfinder", status="ok", results_count=len(found or {})),
                    sources_without_key=no_key or [],
                )
            ),
        )
    )
    stack.enter_context(
        patch(p + "resolve_a", new=AsyncMock(side_effect=resolve or (lambda h: ["93.184.216.34"])))
    )
    probe_mock = AsyncMock(
        return_value=(probes or [], [ToolRun(tool="http-probe (built-in)", status="ok")])
    )
    stack.enter_context(patch(p + "http_probe.probe_hosts", new=probe_mock))
    return probe_mock


async def test_degraded_when_no_tools_installed():
    probe = HttpProbeResult(
        url="https://acme.test/", status_code=200, title="Acme", server=None, host="acme.test"
    )
    with ExitStack() as stack:
        _patches(stack, probes=[probe])
        result = await run_recon("acme.test")

    assert result.degraded is True
    assert result.tool_availability == {"subfinder": False, "httpx": False, "tlsx": False}
    hosts = {a.host: a for a in result.assets}
    assert hosts["acme.test"].ips == ["93.184.216.34"]
    assert hosts["acme.test"].live is True
    assert any("subfinder is not installed" in n for n in result.notes)
    assert any(r.tool == "subfinder" and r.status == "skipped" for r in result.tool_runs)
    assert any(r.tool == "dns (built-in)" for r in result.tool_runs)


async def test_not_degraded_when_all_tools_available_and_sources_kept():
    with ExitStack() as stack:
        _patches(
            stack,
            subfinder=True,
            httpx_bin=True,
            found={"api.acme.test": ["crtsh", "alienvault"]},
        )
        stack.enter_context(
            patch(
                "sentinel_recon.phase.tlsx_wrapper.is_available", new=AsyncMock(return_value=True)
            )
        )
        result = await run_recon("acme.test")

    assert result.degraded is False
    by_host = {a.host: a for a in result.assets}
    assert by_host["api.acme.test"].sources == ["crtsh", "alienvault"]
    assert by_host["api.acme.test"].source == "subfinder"
    assert by_host["acme.test"].source == "root_domain"


async def test_www_dropped_when_it_does_not_resolve():
    with ExitStack() as stack:
        _patches(stack, resolve=lambda h: [] if h.startswith("www.") else ["93.184.216.34"])
        result = await run_recon("acme.test")
    assert [a.host for a in result.assets] == ["acme.test"]


async def test_wildcard_dns_noted():
    with ExitStack() as stack:
        _patches(stack, wildcard=True)
        result = await run_recon("acme.test")
    assert result.wildcard_dns_suspected is True
    assert any("wildcard DNS" in n for n in result.notes)


async def test_cap_always_keeps_root_and_www_and_lists_the_rest():
    found = {f"a{i:03d}.acme.test": ["crtsh"] for i in range(200)}
    found["www.acme.test"] = ["crtsh"]
    with ExitStack() as stack:
        probe_mock = _patches(stack, subfinder=True, found=found)
        result = await run_recon("acme.test")

    probed = probe_mock.call_args.args[0]
    assert len(probed) == MAX_CANDIDATE_HOSTS
    assert probed[:2] == ["acme.test", "www.acme.test"]
    capped = [a for a in result.assets if a.scope_status == "capped"]
    assert len(capped) == 202 - MAX_CANDIDATE_HOSTS
    assert any("were checked this scan" in n for n in result.notes)


async def test_excluded_host_is_not_resolved_or_probed():
    resolved: list[str] = []

    def resolve(host):
        resolved.append(host)
        return ["93.184.216.34"]

    with ExitStack() as stack:
        probe_mock = _patches(
            stack, subfinder=True, found={"admin.acme.test": ["crtsh"]}, resolve=resolve
        )
        result = await run_recon(
            "acme.test",
            host_check=lambda h: "excluded by rule" if h == "admin.acme.test" else None,
        )

    assert "admin.acme.test" not in resolved
    assert "admin.acme.test" not in probe_mock.call_args.args[0]
    admin = next(a for a in result.assets if a.host == "admin.acme.test")
    assert admin.scope_status == "excluded"
    assert admin.scope_reason == "excluded by rule"


async def test_private_address_host_not_probed_unless_allowed():
    def resolve(host):
        return ["10.0.0.5"] if host == "internal.acme.test" else ["93.184.216.34"]

    with ExitStack() as stack:
        probe_mock = _patches(
            stack, subfinder=True, found={"internal.acme.test": ["crtsh"]}, resolve=resolve
        )
        result = await run_recon("acme.test")
    assert "internal.acme.test" not in probe_mock.call_args.args[0]
    internal = next(a for a in result.assets if a.host == "internal.acme.test")
    assert internal.scope_status == "private_ip"
    assert "10.0.0.5" in (internal.scope_reason or "")

    with ExitStack() as stack:
        probe_mock = _patches(
            stack, subfinder=True, found={"internal.acme.test": ["crtsh"]}, resolve=resolve
        )
        await run_recon("acme.test", allow_private_ips=True)
    assert "internal.acme.test" in probe_mock.call_args.args[0]


async def test_rate_passed_to_prober_and_keyless_sources_noted():
    with ExitStack() as stack:
        probe_mock = _patches(stack, subfinder=True, no_key=["shodan", "censys"])
        result = await run_recon("acme.test", requests_per_second=2)
    assert probe_mock.call_args.kwargs["requests_per_second"] == 2
    assert any("no API key" in n and "shodan" in n for n in result.notes)


async def test_log_callback_announces_commands():
    lines: list[tuple[str, str]] = []
    with ExitStack() as stack:
        _patches(stack, subfinder=True, httpx_bin=True)
        await run_recon("acme.test", log=lambda level, msg: lines.append((level, msg)))
    assert any(msg.startswith("Running: subfinder -d acme.test") for _, msg in lines)
    assert any("pd-httpx" in msg and "-rl" in msg for _, msg in lines)


def test_asset_tech_prefers_detections_over_raw_server_header():
    from sentinel_recon.models import DiscoveredAsset

    detected = DiscoveredAsset(
        host="a",
        source="root_domain",
        http_probes=[
            HttpProbeResult(
                url="u", status_code=200, title=None, server="nginx/1.2", tech=["PHP:8"]
            )
        ],
    )
    assert detected.tech == ["PHP:8"]
    header_only = DiscoveredAsset(
        host="a",
        source="root_domain",
        http_probes=[HttpProbeResult(url="u", status_code=200, title=None, server="nginx/1.2")],
    )
    assert header_only.tech == ["nginx/1.2"]
