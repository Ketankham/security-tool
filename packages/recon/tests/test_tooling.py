from sentinel_recon.tooling import run_tool, tool_available


def test_tool_available_true_for_a_real_binary():
    assert tool_available("sh") is True


def test_tool_available_false_for_nonexistent_binary():
    assert tool_available("definitely-not-a-real-binary-xyz") is False


async def test_run_tool_returns_not_ran_when_binary_missing():
    result = await run_tool("definitely-not-a-real-binary-xyz", ["-v"])
    assert result.ran is False


async def test_run_tool_captures_stdout_of_a_real_command():
    result = await run_tool("echo", ["hello"])
    assert result.ran is True
    assert result.stdout.strip() == "hello"
    assert result.returncode == 0


async def test_run_tool_times_out():
    result = await run_tool("sleep", ["5"], timeout_s=0.1)
    assert result.ran is True
    assert result.timed_out is True


async def test_looks_like_projectdiscovery_tool_false_when_missing():
    from sentinel_recon.tooling import looks_like_projectdiscovery_tool

    assert await looks_like_projectdiscovery_tool("definitely-not-a-real-binary-xyz") is False


async def test_looks_like_projectdiscovery_tool_true_when_version_flag_exits_zero():
    from unittest.mock import AsyncMock, patch

    from sentinel_recon.tooling import ToolRunResult, looks_like_projectdiscovery_tool

    with (
        patch("sentinel_recon.tooling.tool_available", return_value=True),
        patch(
            "sentinel_recon.tooling.run_tool",
            new=AsyncMock(return_value=ToolRunResult(ran=True, returncode=0, stdout="v1.2.3")),
        ),
    ):
        assert await looks_like_projectdiscovery_tool("httpx") is True


async def test_looks_like_projectdiscovery_tool_false_for_shadowing_binary():
    """Regression test for a real bug found in this sandbox: the *Python*
    httpx library installs its own `httpx` console script on PATH, which
    (without its optional [cli] extras) exits non-zero on every invocation.
    Naive `shutil.which`-only availability checks would silently treat it
    as ProjectDiscovery's httpx and get zero real probe results back —
    exactly the false-negative failure mode docs/04-edge-cases.md §B and §G
    exist to prevent."""
    from unittest.mock import AsyncMock, patch

    from sentinel_recon.tooling import ToolRunResult, looks_like_projectdiscovery_tool

    with (
        patch("sentinel_recon.tooling.tool_available", return_value=True),
        patch(
            "sentinel_recon.tooling.run_tool",
            new=AsyncMock(
                return_value=ToolRunResult(
                    ran=True,
                    returncode=1,
                    stderr="The httpx command line client could not run because the "
                    "required dependencies were not installed.",
                )
            ),
        ),
    ):
        assert await looks_like_projectdiscovery_tool("httpx") is False
