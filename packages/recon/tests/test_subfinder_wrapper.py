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


def test_parse_hosts_keeps_sources_in_both_formats_and_drops_junk():
    from sentinel_recon.subfinder_wrapper import parse_hosts

    stdout = "\n".join(
        [
            '{"host":"api.acme.test","input":"acme.test","sources":["crtsh","alienvault"]}',
            '{"host":"API.acme.test.","source":"hackertarget"}',
            '{"host":"*.acme.test","sources":["crtsh"]}',
            '{"host":"evil.example","sources":["crtsh"]}',
            '{"host":"notacme.test","sources":["crtsh"]}',
            "[1,2]",
        ]
    )
    assert parse_hosts(stdout, "acme.test") == {
        "api.acme.test": ["alienvault", "crtsh", "hackertarget"]
    }


async def test_run_subfinder_reports_keyless_and_failed_sources():
    from sentinel_recon.subfinder_wrapper import run_subfinder

    stderr = (
        "[DBG] Cannot use the shodan source because there was no API key/secret defined for it.\n"
        "[WRN] Could not run source crtsh: unexpected status code 503\n"
    )
    with (
        patch(
            "sentinel_recon.subfinder_wrapper.run_tool",
            new=AsyncMock(
                return_value=ToolRunResult(
                    ran=True,
                    stdout='{"host":"a.acme.test","sources":["alienvault"]}\n',
                    stderr=stderr,
                    returncode=0,
                    command="subfinder -d acme.test",
                )
            ),
        ),
        patch(
            "sentinel_recon.subfinder_wrapper.tool_version", new=AsyncMock(return_value="v2.17.0")
        ),
    ):
        outcome = await run_subfinder("acme.test")
    assert outcome.hosts == {"a.acme.test": ["alienvault"]}
    assert outcome.sources_without_key == ["shodan"]
    assert outcome.sources_failed == ["crtsh"]
    assert outcome.run.status == "ok"
    assert outcome.run.version == "v2.17.0"
    assert outcome.run.results_count == 1


async def test_run_subfinder_keeps_partial_results_on_timeout():
    from sentinel_recon.subfinder_wrapper import run_subfinder

    with patch(
        "sentinel_recon.subfinder_wrapper.run_tool",
        new=AsyncMock(
            return_value=ToolRunResult(ran=True, stdout='{"host":"a.acme.test"}\n', timed_out=True)
        ),
    ):
        outcome = await run_subfinder("acme.test")
    assert outcome.run.status == "timed_out"
    assert list(outcome.hosts) == ["a.acme.test"]


def test_build_args_full_profile_adds_all_sources_and_more_time():
    from sentinel_recon.subfinder_wrapper import build_args

    light, full = build_args("acme.test"), build_args("acme.test", all_sources=True)
    assert "-all" not in light and "-all" in full
    assert light[light.index("-max-time") + 1] == "2"
    assert full[full.index("-max-time") + 1] == "5"
    assert light[:2] == ["-d", "acme.test"]
