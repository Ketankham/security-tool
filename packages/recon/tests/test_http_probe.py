import httpx
import respx
from sentinel_recon.http_probe import probe_via_python


async def test_probe_via_python_extracts_title_and_status():
    with respx.mock:
        respx.get("https://acme.test/").mock(
            return_value=httpx.Response(
                200, headers={"server": "nginx"}, html="<html><title>Acme</title></html>"
            )
        )
        results = await probe_via_python(["acme.test"])
    assert len(results) == 1
    assert results[0].status_code == 200
    assert results[0].title == "Acme"
    assert results[0].server == "nginx"


async def test_probe_via_python_falls_back_to_http_on_https_failure():
    with respx.mock:
        respx.get("https://acme.test/").mock(side_effect=httpx.ConnectError("no tls"))
        respx.get("http://acme.test/").mock(return_value=httpx.Response(200))
        results = await probe_via_python(["acme.test"])
    assert len(results) == 1
    assert results[0].url.startswith("http://")
    assert results[0].status_code == 200


async def test_probe_via_python_reports_error_when_both_schemes_fail():
    with respx.mock:
        respx.get("https://acme.test/").mock(side_effect=httpx.ConnectError("down"))
        respx.get("http://acme.test/").mock(side_effect=httpx.ConnectError("down"))
        results = await probe_via_python(["acme.test"])
    assert len(results) == 1
    assert results[0].status_code is None
    assert results[0].error is not None


def test_parse_binary_output_maps_success_and_failure_lines():
    from sentinel_recon.http_probe import parse_binary_output

    stdout = "\n".join(
        [
            '{"url":"http://localhost:8766","input":"localhost:8766","title":"Vuln Shop",'
            '"webserver":"Apache/2.4.41","content_type":"text/html","status_code":200,'
            '"tech":["PHP:7.4.3","Ubuntu"],"cdn_name":"cloudflare","failed":false}',
            '{"url":"http://down.acme.test","input":"down.acme.test",'
            '"error":"cause=\\"no address found for host\\"","status_code":0,"failed":true}',
        ]
    )
    ok, failed = parse_binary_output(stdout)
    assert ok.host == "localhost" and ok.status_code == 200 and ok.tech == ["PHP:7.4.3", "Ubuntu"]
    assert ok.cdn == "cloudflare" and ok.content_type == "text/html"
    assert failed.status_code is None and failed.host == "down.acme.test"
    assert "no address" in (failed.error or "")


def test_build_args_applies_scan_rate():
    from sentinel_recon.http_probe import build_args

    args = build_args(2.0)
    assert args[args.index("-rl") + 1] == "2"
    assert args[args.index("-t") + 1] == "2"
    assert "-td" in args and "-probe" in args and "-json" in args
    assert build_args(0.5)[build_args(0.5).index("-rl") + 1] == "1"


async def test_probe_via_python_respects_rate():
    import time

    with respx.mock:
        respx.get(url__regex=r"https://h\d\.acme\.test/").mock(return_value=httpx.Response(200))
        start = time.monotonic()
        results = await probe_via_python(
            [f"h{i}.acme.test" for i in range(5)], requests_per_second=10
        )
        elapsed = time.monotonic() - start
    assert len(results) == 5
    assert elapsed >= 0.35  # 5 starts at 10/s: ~0.4s, not instant


async def test_probe_hosts_falls_back_to_builtin_when_binary_fails():
    from unittest.mock import AsyncMock, patch

    from sentinel_recon.http_probe import probe_hosts
    from sentinel_recon.models import ToolRun

    with (
        patch(
            "sentinel_recon.http_probe.probe_via_binary",
            new=AsyncMock(return_value=([], ToolRun(tool="httpx", status="timed_out"))),
        ),
        respx.mock,
    ):
        respx.get("https://acme.test/").mock(return_value=httpx.Response(200))
        probes, runs = await probe_hosts(["acme.test"], binary_available=True)
    assert [r.status for r in runs] == ["timed_out", "ok"]
    assert probes[0].status_code == 200
