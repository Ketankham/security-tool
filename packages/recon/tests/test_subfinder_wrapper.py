from unittest.mock import AsyncMock, patch

from sentinel_recon.subfinder_wrapper import enumerate_subdomains
from sentinel_recon.tooling import ToolRunResult


async def test_enumerate_subdomains_parses_ndjson():
    fake_stdout = '{"host": "api.acme.test"}\n{"host": "www.acme.test"}\n'
    with patch(
        "sentinel_recon.subfinder_wrapper.run_tool",
        new=AsyncMock(return_value=ToolRunResult(ran=True, stdout=fake_stdout, returncode=0)),
    ):
        hosts = await enumerate_subdomains("acme.test")
    assert hosts == ["api.acme.test", "www.acme.test"]


async def test_enumerate_subdomains_returns_empty_when_not_installed():
    with patch(
        "sentinel_recon.subfinder_wrapper.run_tool",
        new=AsyncMock(return_value=ToolRunResult(ran=False)),
    ):
        hosts = await enumerate_subdomains("acme.test")
    assert hosts == []


async def test_enumerate_subdomains_ignores_malformed_lines():
    with patch(
        "sentinel_recon.subfinder_wrapper.run_tool",
        new=AsyncMock(
            return_value=ToolRunResult(
                ran=True, stdout='not json\n{"host": "x.acme.test"}\n', returncode=0
            )
        ),
    ):
        hosts = await enumerate_subdomains("acme.test")
    assert hosts == ["x.acme.test"]
