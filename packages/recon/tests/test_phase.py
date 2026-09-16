from unittest.mock import AsyncMock, patch

from sentinel_recon.models import HttpProbeResult
from sentinel_recon.phase import run_recon


async def test_run_recon_degraded_true_when_no_tools_installed():
    with (
        patch(
            "sentinel_recon.phase.subfinder_wrapper.is_available", new=AsyncMock(return_value=False)
        ),
        patch(
            "sentinel_recon.phase.http_probe.is_available",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "sentinel_recon.phase.tlsx_wrapper.is_available",
            new=AsyncMock(return_value=False),
        ),
        patch("sentinel_recon.phase.detect_wildcard_dns", new=AsyncMock(return_value=False)),
        patch("sentinel_recon.phase.resolve_a", new=AsyncMock(return_value=["1.2.3.4"])),
        patch(
            "sentinel_recon.phase.http_probe.probe_hosts",
            new=AsyncMock(
                return_value=[
                    HttpProbeResult(
                        url="https://acme.test/", status_code=200, title="Acme", server=None
                    )
                ]
            ),
        ),
    ):
        result = await run_recon("acme.test")

    assert result.degraded is True
    assert result.tool_availability == {"subfinder": False, "httpx": False, "tlsx": False}
    assert len(result.assets) == 1
    assert result.assets[0].host == "acme.test"
    assert result.assets[0].ips == ["1.2.3.4"]
    assert len(result.assets[0].http_probes) == 1
    assert any("subfinder is not installed" in n for n in result.notes)


async def test_run_recon_not_degraded_when_all_tools_available():
    with (
        patch(
            "sentinel_recon.phase.subfinder_wrapper.is_available", new=AsyncMock(return_value=True)
        ),
        patch(
            "sentinel_recon.phase.http_probe.is_available",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "sentinel_recon.phase.tlsx_wrapper.is_available",
            new=AsyncMock(return_value=True),
        ),
        patch("sentinel_recon.phase.detect_wildcard_dns", new=AsyncMock(return_value=False)),
        patch(
            "sentinel_recon.phase.subfinder_wrapper.enumerate_subdomains",
            new=AsyncMock(return_value=["api.acme.test"]),
        ),
        patch("sentinel_recon.phase.resolve_a", new=AsyncMock(return_value=["1.2.3.4"])),
        patch("sentinel_recon.phase.http_probe.probe_hosts", new=AsyncMock(return_value=[])),
    ):
        result = await run_recon("acme.test")

    assert result.degraded is False
    assert {a.host for a in result.assets} == {"acme.test", "api.acme.test"}


async def test_run_recon_notes_wildcard_dns():
    with (
        patch(
            "sentinel_recon.phase.subfinder_wrapper.is_available", new=AsyncMock(return_value=False)
        ),
        patch(
            "sentinel_recon.phase.http_probe.is_available",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "sentinel_recon.phase.tlsx_wrapper.is_available",
            new=AsyncMock(return_value=False),
        ),
        patch("sentinel_recon.phase.detect_wildcard_dns", new=AsyncMock(return_value=True)),
        patch("sentinel_recon.phase.resolve_a", new=AsyncMock(return_value=["1.2.3.4"])),
        patch("sentinel_recon.phase.http_probe.probe_hosts", new=AsyncMock(return_value=[])),
    ):
        result = await run_recon("acme.test")

    assert result.wildcard_dns_suspected is True
    assert any("wildcard DNS" in n for n in result.notes)


async def test_run_recon_caps_candidate_hosts():
    many_hosts = [f"h{i}.acme.test" for i in range(200)]
    with (
        patch(
            "sentinel_recon.phase.subfinder_wrapper.is_available", new=AsyncMock(return_value=True)
        ),
        patch(
            "sentinel_recon.phase.http_probe.is_available",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "sentinel_recon.phase.tlsx_wrapper.is_available",
            new=AsyncMock(return_value=False),
        ),
        patch("sentinel_recon.phase.detect_wildcard_dns", new=AsyncMock(return_value=False)),
        patch(
            "sentinel_recon.phase.subfinder_wrapper.enumerate_subdomains",
            new=AsyncMock(return_value=many_hosts),
        ),
        patch("sentinel_recon.phase.resolve_a", new=AsyncMock(return_value=["1.2.3.4"])),
        patch("sentinel_recon.phase.http_probe.probe_hosts", new=AsyncMock(return_value=[])),
    ):
        result = await run_recon("acme.test")

    assert len(result.assets) <= 50
    assert any("capped" in n for n in result.notes)
