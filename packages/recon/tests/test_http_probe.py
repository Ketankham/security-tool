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
