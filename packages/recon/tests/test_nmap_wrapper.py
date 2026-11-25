"""nmap wrapper: argument list, XML parsing and run_nmap.

IMPORTANT: real nmap is NOT available where these tests were written (no apt, no
docker) and is not installed in the worker image either (NPSL licence, see the
nmap_wrapper docstring). Everything here runs against hand-written XML fixtures
and a fake `nmap` script earlier on PATH. The fixtures follow the structure of
nmap 7.93 ``-oX`` output, but no test proves the argument list is accepted by
the real binary: check it on a machine that has nmap before enabling the tool.
"""

# ruff: noqa: E501 -- the XML fixtures keep nmap's own long lines

import asyncio
import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest
from sentinel_core.redact import REDACTED
from sentinel_recon import nmap_wrapper
from sentinel_recon.nmap_wrapper import (
    MAX_NORMAL_OUTPUT_BYTES,
    MAX_PORTS,
    MAX_SCRIPT_OUTPUT_CHARS,
    ScriptOutput,
    ServiceInfo,
    build_args,
    parse_xml,
    run_nmap,
)
from sentinel_recon.runs import skipped_run, tool_run_from

# --- fixtures ------------------------------------------------------------------

BEARER_SECRET = "Zx9Qk2LmPv7RtW4yUb8N"
JWT_SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"


def nmap_xml(ports_xml: str, host_extra: str = "") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.93 scan initiated Tue Nov 25 10:00:00 2026 as: nmap -sT -Pn -n -sV -oX - 203.0.113.7 -->
<nmaprun scanner="nmap" args="nmap -sT -Pn -n -sV -oX - 203.0.113.7" start="1795600000" startstr="Tue Nov 25 10:00:00 2026" version="7.93" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="6" services="22,25,80,443,3306,8080"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1795600001" endtime="1795600030"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="203.0.113.7" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="closed" count="2">
<extrareasons reason="conn-refused" count="2" proto="tcp" ports="3306,8080"/>
</extraports>
{ports_xml}
</ports>
{host_extra}<times srtt="1000" rttvar="1000" to="100000"/>
</host>
<runstats><finished time="1795600030" timestr="Tue Nov 25 10:00:30 2026" summary="Nmap done at Tue Nov 25 10:00:30 2026; 1 IP address (1 host up) scanned in 30.00 seconds" elapsed="30.00" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""


SSH_PORT = """<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.4" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service><script id="ssh-hostkey" output="&#xa;  256 3b:a1:cc:0e:7c:19:5d:2f:aa:01:9e:34:55:0c:12:d7 (ECDSA)&#xa;  256 9a:7e:44:b1:8d:20:61:ce:b3:f7:02:6a:19:dd:40:88 (ED25519)"><table>
<elem key="type">ecdsa-sha2-nistp256</elem>
</table>
</script></port>"""

HTTP_PORT = """<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu" tunnel="" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service><script id="http-title" output="Welcome to nginx!"/><script id="http-server-header" output="nginx/1.18.0 (Ubuntu)"/></port>"""

HTTPS_PORT = """<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/></port>"""

FILTERED_PORT = """<port protocol="tcp" portid="25"><state state="filtered" reason="no-response" reason_ttl="0"/><service name="smtp" method="table" conf="3"/></port>"""

CLOSED_PORT = """<port protocol="tcp" portid="3306"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="mysql" method="table" conf="3"/></port>"""

SECRET_PORT = f"""<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http-proxy" method="probed" conf="8"/><script id="banner" output="220 api ready&#xa;Authorization: Bearer {BEARER_SECRET}&#xa;see https://svc.example/cb?token=abcd1234efgh&amp;page=2&#xa;jwt {JWT_SECRET}"/></port>"""

FULL_XML = nmap_xml(
    "\n".join([SSH_PORT, FILTERED_PORT, HTTP_PORT, HTTPS_PORT, CLOSED_PORT, SECRET_PORT])
)


# --- build_args ----------------------------------------------------------------------


def test_build_args_production_golden():
    assert build_args(
        "203.0.113.7", [22, 80, 443], environment="production", pps=100, normal_out="/tmp/n.txt"
    ) == [
        "-sT", "-Pn", "-n", "--unprivileged", "-sV",
        "--script", "default and safe and not http-*",
        "--script-timeout", "60s", "--host-timeout", "900s", "--max-retries", "2",
        "--max-rate", "100",
        "--reason", "-p", "22,80,443",
        "-oX", "-", "-oN", "/tmp/n.txt",
        "203.0.113.7",
    ]  # fmt: skip


def test_build_args_staging_uses_the_default_script_set():
    args = build_args("203.0.113.7", [8080], environment="staging", pps=50, normal_out="/tmp/n.txt")
    assert args[args.index("--script") + 1] == "default"
    assert args[args.index("--max-rate") + 1] == "50"
    assert args[args.index("-p") + 1] == "8080"


def test_build_args_ipv6_adds_dash_6_in_front():
    args = build_args("2001:db8::1", [22], environment="production", pps=100, normal_out="n.txt")
    assert args[0] == "-6" and args[-1] == "2001:db8::1"
    assert "-6" not in build_args(
        "203.0.113.7", [22], environment="production", pps=1, normal_out="n"
    )


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize("pps", [1, 50, 200])
def test_build_args_is_connect_scan_without_syn_udp_os_or_default_scripts_shortcut(
    environment, pps
):
    args = build_args("203.0.113.7", [22], environment=environment, pps=pps, normal_out="n.txt")
    assert "-sT" in args and "-Pn" in args and "-n" in args and "--unprivileged" in args
    for forbidden in ("-sS", "-sU", "-O", "-A", "-sC", "-T4", "-T5", "--osscan-guess", "-sn"):
        assert forbidden not in args
    assert args[args.index("--max-rate") + 1] == str(pps)  # a rate is always present
    assert "--script-timeout" in args and "--host-timeout" in args


@pytest.mark.parametrize(("pps", "expected"), [(0, "1"), (-3, "1"), (0.2, "1"), (9.9, "9")])
def test_build_args_max_rate_is_a_positive_integer(pps, expected):
    args = build_args("203.0.113.7", [22], environment="production", pps=pps, normal_out="n.txt")
    assert args[args.index("--max-rate") + 1] == expected


def test_build_args_production_script_expression_excludes_http_scripts():
    args = build_args("203.0.113.7", [80], environment="production", pps=100, normal_out="n")
    assert "not http-*" in args[args.index("--script") + 1]


@pytest.mark.parametrize("bad", ["", "example.com", "-oN", "203.0.113.7 -p-", "999.1.1.1"])
def test_build_args_refuses_anything_that_is_not_an_ip_address(bad):
    with pytest.raises(ValueError):
        build_args(bad, [22], environment="production", pps=100, normal_out="n")


@pytest.mark.parametrize("ports", [[], [0], [65536], [-1], [22, "80"], [True], [22.0]])
def test_build_args_refuses_empty_or_invalid_ports(ports):
    with pytest.raises(ValueError):
        build_args("203.0.113.7", ports, environment="production", pps=100, normal_out="n")


# --- parse_xml ----------------------------------------------------------------------


def by_port(services: list[ServiceInfo]) -> dict[int, ServiceInfo]:
    return {s.port: s for s in services}


def test_parse_realistic_xml_with_several_ports():
    services, error = parse_xml(FULL_XML)
    assert error is None
    assert [s.port for s in services] == [22, 25, 80, 443, 3306, 8080]
    ssh = by_port(services)[22]
    assert ssh == ServiceInfo(
        port=22,
        protocol="tcp",
        state="open",
        reason="syn-ack",
        service="ssh",
        product="OpenSSH",
        version="8.9p1 Ubuntu 3ubuntu0.4",
        extra_info="Ubuntu Linux; protocol 2.0",
        confidence=10,
        method="probed",
        tunnel=None,
        cpes=("cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"),
        scripts=(
            ScriptOutput(
                id="ssh-hostkey",
                output=(
                    "\n  256 3b:a1:cc:0e:7c:19:5d:2f:aa:01:9e:34:55:0c:12:d7 (ECDSA)"
                    "\n  256 9a:7e:44:b1:8d:20:61:ce:b3:f7:02:6a:19:dd:40:88 (ED25519)"
                ),
            ),
        ),
    )
    http = by_port(services)[80]
    assert (http.service, http.product, http.version, http.extra_info) == (
        "http",
        "nginx",
        "1.18.0",
        "Ubuntu",
    )
    assert [(s.id, s.output) for s in http.scripts] == [
        ("http-title", "Welcome to nginx!"),
        ("http-server-header", "nginx/1.18.0 (Ubuntu)"),
    ]
    assert by_port(services)[443].tunnel == "ssl"
    assert by_port(services)[443].version is None and by_port(services)[443].scripts == ()


def test_closed_and_filtered_ports_are_returned_with_their_state():
    services, error = parse_xml(FULL_XML)
    assert error is None
    table = by_port(services)
    assert (table[25].state, table[25].reason, table[25].method) == (
        "filtered",
        "no-response",
        "table",
    )
    assert (table[3306].state, table[3306].reason) == ("closed", "conn-refused")
    assert [s.port for s in services if s.state == "open"] == [22, 80, 443, 8080]


def test_script_output_with_secrets_comes_out_redacted():
    services, error = parse_xml(FULL_XML)
    assert error is None
    output = by_port(services)[8080].scripts[0].output
    assert BEARER_SECRET not in output
    assert JWT_SECRET not in output
    assert "abcd1234efgh" not in output
    assert REDACTED in output
    assert "220 api ready" in output  # the harmless text is kept


def test_a_secret_near_the_length_cap_is_redacted():
    padding = "x " * ((MAX_SCRIPT_OUTPUT_CHARS - 20) // 2)
    token = "Bearer " + "AbCdEf0123456789" * 3
    port = (
        '<port protocol="tcp" portid="9000"><state state="open"/>'
        f'<script id="s" output="{padding}{token}"/></port>'
    )
    services, error = parse_xml(nmap_xml(port))
    assert error is None
    out = services[0].scripts[0].output
    assert "AbCdEf0123" not in out


def test_long_script_output_is_capped_at_4000_characters():
    long = "A" * 20_000
    port = f'<port protocol="tcp" portid="22"><state state="open"/><script id="big" output="{long}"/></port>'
    services, error = parse_xml(nmap_xml(port))
    assert error is None
    out = services[0].scripts[0].output
    assert len(out) == MAX_SCRIPT_OUTPUT_CHARS == 4000
    assert out.endswith("…")


def test_output_just_under_the_cap_is_untouched():
    text = "B" * 4000
    port = f'<port protocol="tcp" portid="22"><state state="open"/><script id="b" output="{text}"/></port>'
    services, _ = parse_xml(nmap_xml(port))
    assert services[0].scripts[0].output == text


def test_service_fields_are_cut_to_the_column_sizes_and_secrets_removed():
    port = (
        '<port protocol="tcp" portid="22"><state state="open"/>'
        f'<service name="{"n" * 300}" product="{"p" * 500}" version="{"v" * 500}" '
        f'extrainfo="{"e" * 900} Bearer {BEARER_SECRET}"/></port>'
    )
    (svc,), error = parse_xml(nmap_xml(port))
    assert error is None
    assert len(svc.service or "") == 100 and len(svc.product or "") == 200
    assert len(svc.version or "") == 100 and len(svc.extra_info or "") <= 300


def test_a_port_with_missing_attributes_is_tolerated():
    xml = nmap_xml(
        '<port portid="21"/>'
        '<port protocol="tcp"><state state="open"/></port>'  # no portid: dropped
        '<port protocol="tcp" portid="notanumber"><state state="open"/></port>'
        '<port protocol="tcp" portid="0"><state state="open"/></port>'
        '<port protocol="tcp" portid="70000"><state state="open"/></port>'
        '<port protocol="tcp" portid="23"><state state="open"/><service/>'
        '<script output="no id"/><script id="ok" output="fine"/></port>'
    )
    services, error = parse_xml(xml)
    assert error is None
    assert [s.port for s in services] == [21, 23]
    first, second = services
    assert (first.protocol, first.state, first.service, first.scripts) == (
        "tcp",
        "unknown",
        None,
        (),
    )
    assert second.state == "open" and [s.id for s in second.scripts] == ["ok"]


def test_unrelated_elements_are_ignored():
    host_extra = '<hostscript><script id="smb-os" output="x"/></hostscript>\n<trace/>\n'
    services, error = parse_xml(nmap_xml(HTTP_PORT, host_extra=host_extra))
    assert error is None and [s.port for s in services] == [80]


def test_host_with_no_ports_gives_no_services_and_no_error():
    services, error = parse_xml(nmap_xml(""))
    assert services == [] and error is None


def test_truncated_xml_keeps_the_complete_ports_and_reports_an_error():
    cut = FULL_XML[: FULL_XML.index('<port protocol="tcp" portid="443">') + 60]
    services, error = parse_xml(cut)
    assert [s.port for s in services] == [22, 25, 80]
    assert error is not None and "could not be fully parsed" in error


@pytest.mark.parametrize("keep", [0, 10, 200, 500, 900])
def test_xml_cut_anywhere_never_raises(keep):
    services, error = parse_xml(FULL_XML[:keep])
    assert isinstance(services, list)
    if keep < len(FULL_XML):
        assert error is not None


@pytest.mark.parametrize(
    "garbage",
    [
        "",
        "   \n",
        "Starting Nmap 7.93\nNmap scan report for 203.0.113.7",
        "<html><body>not nmap</body></html>",
        "<<<<>>>>",
        "\x00\x01\x02",
        "<nmaprun><host><ports><port protocol='tcp' portid='22'><state state='open'/></port>",
        "{}",
    ],
)
def test_garbage_gives_an_error_and_never_raises(garbage):
    services, error = parse_xml(garbage)
    assert error is not None
    assert all(isinstance(s, ServiceInfo) for s in services)


def test_empty_xml_error_message():
    assert parse_xml("") == ([], "nmap produced no XML output")


def test_xml_that_declares_entities_is_refused():
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa">]>'
        '<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<script id="x" output="&a;&a;"/></port></ports></host></nmaprun>'
    )
    services, error = parse_xml(bomb)
    assert services == [] and error is not None and "entities" in error


def test_non_nmap_xml_is_an_error():
    services, error = parse_xml("<root><a/></root>")
    assert services == [] and error == "nmap output was not nmap XML"


# --- fake binaries ---------------------------------------------------------------------


def install_fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    """A python script called `nmap` first on PATH."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "nmap"
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return script


def alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


async def wait_dead(*pids: int, within: float = 3.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while loop.time() < deadline:
        if not any(alive(p) for p in pids):
            return True
        await asyncio.sleep(0.05)
    return False


async def wait_for_file(path: Path, within: float = 5.0) -> str:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while loop.time() < deadline:
        if path.exists() and path.read_text().strip():
            return path.read_text()
        await asyncio.sleep(0.05)
    raise AssertionError(f"{path} never appeared")


def fake_nmap_script(xml: str, normal: str = "Nmap scan report for 203.0.113.7\n", extra: str = ""):
    """A fake nmap: records argv, writes ``normal`` to the -oN file, prints ``xml``."""
    return f"""
        import json, os, sys
        argv = sys.argv[1:]
        record = os.environ.get("FAKE_NMAP_ARGV")
        if record:
            open(record, "w").write(json.dumps(argv))
        normal_path = argv[argv.index("-oN") + 1]
        open(normal_path, "w").write({normal!r})
        sys.stdout.write({xml!r})
        {extra}
    """


async def test_run_nmap_parses_the_xml_and_returns_the_normal_output(tmp_path, monkeypatch):
    argv_file = tmp_path / "argv.json"
    monkeypatch.setenv("FAKE_NMAP_ARGV", str(argv_file))
    install_fake(
        tmp_path,
        monkeypatch,
        fake_nmap_script(
            FULL_XML, normal="Nmap scan report for 203.0.113.7\nPORT   STATE SERVICE\n"
        ),
    )
    run = await run_nmap("203.0.113.7", [443, 22, 80, 22, 8080], environment="production", pps=100)
    assert run.result.ran and run.result.returncode == 0
    assert run.skipped_reason is None and not run.skipped and not run.not_installed
    assert run.stop_reason is None and run.parse_error is None and not run.failed
    assert [s.port for s in run.services if s.state == "open"] == [22, 80, 443, 8080]
    assert run.normal_output == "Nmap scan report for 203.0.113.7\nPORT   STATE SERVICE\n"

    argv = json.loads(argv_file.read_text())
    normal_path = argv[argv.index("-oN") + 1]
    assert argv == build_args(
        "203.0.113.7",
        [22, 80, 443, 8080],  # sorted and de-duplicated
        environment="production",
        pps=100,
        normal_out=normal_path,
    )
    assert not Path(normal_path).exists()  # the temp dir is gone
    assert (
        tool_run_from("nmap", run.result, binary="nmap", version="7.93", results_count=4).status
        == "ok"
    )


async def test_the_stored_stdout_and_normal_output_are_redacted(tmp_path, monkeypatch):
    normal = f"| banner: Authorization: Bearer {BEARER_SECRET}\n| more text\n"
    install_fake(
        tmp_path,
        monkeypatch,
        fake_nmap_script(
            FULL_XML,
            normal=normal,
            extra=f"sys.stderr.write('warn: Authorization: Bearer {BEARER_SECRET}\\n')",
        ),
    )
    run = await run_nmap("203.0.113.7", [8080], environment="staging", pps=100)
    for text in (run.result.stdout, run.result.stderr, run.normal_output):
        assert BEARER_SECRET not in text
    assert REDACTED in run.normal_output and "more text" in run.normal_output
    assert "Nmap scan report" not in run.result.stdout  # still the XML
    assert 'portid="8080"' in run.result.stdout
    # the parsed services came from the unredacted XML and are redacted separately
    assert BEARER_SECRET not in repr(run.services)


async def test_the_normal_output_is_capped_at_512_kib(tmp_path, monkeypatch):
    big = "line of normal output with some words\n" * 40_000  # ~1.5 MB
    install_fake(tmp_path, monkeypatch, fake_nmap_script(FULL_XML, normal=big))
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    assert 0 < len(run.normal_output.encode()) <= MAX_NORMAL_OUTPUT_BYTES == 512 * 1024
    assert run.normal_output.startswith("line of normal output")


async def test_no_normal_output_file_gives_an_empty_string(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, f"import sys\nsys.stdout.write({FULL_XML!r})\n")
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    assert run.normal_output == "" and run.parse_error is None and len(run.services) == 6


async def test_more_than_50_ports_skips_nmap_without_starting_it(tmp_path, monkeypatch):
    marker = tmp_path / "started"
    install_fake(tmp_path, monkeypatch, f"open({str(marker)!r}, 'w').write('x')\n")
    run = await run_nmap(
        "203.0.113.7", list(range(1, MAX_PORTS + 2)), environment="production", pps=100
    )
    assert run.skipped is True
    assert run.skipped_reason == "skipped: more than 50 open ports"
    assert run.result.ran is False and run.services == [] and run.normal_output == ""
    assert run.not_installed is False and run.failed is False
    assert not marker.exists()
    tool_run = skipped_run("nmap", run.skipped_reason)
    assert (tool_run.status, tool_run.skip_reason) == ("skipped", run.skipped_reason)


async def test_exactly_50_ports_still_runs(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, fake_nmap_script(nmap_xml("")))
    run = await run_nmap(
        "203.0.113.7", list(range(1, MAX_PORTS + 1)), environment="production", pps=100
    )
    assert run.skipped is False and run.result.ran is True


async def test_duplicates_do_not_count_towards_the_50_port_limit(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, fake_nmap_script(nmap_xml("")))
    run = await run_nmap("203.0.113.7", [22] * 80, environment="production", pps=100)
    assert run.skipped is False and run.result.ran is True


async def test_no_ports_is_skipped(tmp_path, monkeypatch):
    marker = tmp_path / "started"
    install_fake(tmp_path, monkeypatch, f"open({str(marker)!r}, 'w').write('x')\n")
    run = await run_nmap("203.0.113.7", [], environment="production", pps=100)
    assert run.skipped_reason == "skipped: no open ports to examine"
    assert not marker.exists()


async def test_invalid_address_or_port_is_a_value_error_and_nothing_starts(tmp_path, monkeypatch):
    marker = tmp_path / "started"
    install_fake(tmp_path, monkeypatch, f"open({str(marker)!r}, 'w').write('x')\n")
    with pytest.raises(ValueError):
        await run_nmap("not-an-ip", [22], environment="production", pps=100)
    with pytest.raises(ValueError):
        await run_nmap("203.0.113.7", [0], environment="production", pps=100)
    assert not marker.exists()


async def test_binary_missing_is_not_installed_not_an_exception(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert await nmap_wrapper.is_available() is False
    assert await nmap_wrapper.version() is None
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    assert run.not_installed is True and run.skipped is False and run.failed is False
    assert run.result.ran is False and run.services == []
    tool_run = tool_run_from("nmap", run.result, binary="nmap", version=None, results_count=0)
    assert tool_run.status == "not_installed"


async def test_is_available_is_true_when_a_binary_is_on_path(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "print('hi')\n")
    assert await nmap_wrapper.is_available() is True


async def test_exit_non_zero_is_failed_and_keeps_what_parsed(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        fake_nmap_script(FULL_XML, extra="sys.stderr.write('QUITTING!\\n')\n        sys.exit(1)"),
    )
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    assert run.result.returncode == 1 and run.failed is True
    assert len(run.services) == 6  # the naabu rows stay; these just add detail
    assert "QUITTING!" in run.result.stderr
    assert (
        tool_run_from("nmap", run.result, binary="nmap", version=None, results_count=0).status
        == "failed"
    )


async def test_garbage_xml_is_a_failed_run_with_a_parse_error(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, fake_nmap_script("this is not xml at all"))
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    assert run.services == [] and run.parse_error is not None and run.failed is True


async def test_empty_stdout_is_a_failed_run(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "pass\n")
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    assert run.parse_error == "nmap produced no XML output" and run.failed is True


async def test_timeout_keeps_the_complete_ports_and_kills_everything(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    partial = FULL_XML[: FULL_XML.index('<port protocol="tcp" portid="443">')]
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, sys, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        sys.stdout.write({partial!r})
        sys.stdout.flush()
        time.sleep(300)
        """,
    )
    run = await run_nmap("203.0.113.7", [22, 80], environment="production", pps=100, timeout_s=2.0)
    assert run.result.timed_out is True and run.stop_reason == "timed out"
    assert run.failed is False  # we stopped it; that is not nmap failing
    assert [s.port for s in run.services] == [22, 25, 80]
    assert run.parse_error is not None  # the cut-off document is reported, not hidden
    me, child = (int(x) for x in pids.read_text().split())
    assert await wait_dead(me, child)
    assert (
        tool_run_from("nmap", run.result, binary="nmap", version=None, results_count=3).status
        == "timed_out"
    )


async def test_timeout_with_no_output_has_no_parse_error(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "import time\ntime.sleep(300)\n")
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100, timeout_s=1.0)
    assert run.stop_reason == "timed out" and run.parse_error is None and run.services == []


async def test_cancel_check_stops_nmap_and_everything_it_started(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        time.sleep(300)
        """,
    )

    async def cancel_check():
        return "alice" if pids.exists() and pids.read_text().strip() else None

    run = await run_nmap(
        "203.0.113.7", [22], environment="production", pps=100, cancel_check=cancel_check
    )
    assert run.result.cancelled is True and run.result.cancelled_by == "alice"
    assert run.stop_reason == "cancelled" and run.failed is False
    me, child = (int(x) for x in pids.read_text().split())
    assert await wait_dead(me, child)
    tool_run = tool_run_from("nmap", run.result, binary="nmap", version=None, results_count=0)
    assert (tool_run.status, tool_run.skip_reason) == ("cancelled", "Cancelled by alice")


async def test_cancelling_the_awaiting_task_kills_the_process_group(tmp_path, monkeypatch):
    pids = tmp_path / "pids"
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import os, subprocess, time
        child = subprocess.Popen(["sleep", "300"])
        open({str(pids)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        time.sleep(300)
        """,
    )
    task = asyncio.create_task(
        run_nmap("203.0.113.7", [22], environment="production", pps=100, timeout_s=120)
    )
    me, child = (int(x) for x in (await wait_for_file(pids)).split())
    assert alive(me) and alive(child)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await wait_dead(me, child)


async def test_huge_xml_output_is_stored_truncated_without_raising(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        f"""
        import sys
        sys.stdout.write({FULL_XML[: FULL_XML.index('<port protocol="tcp" portid="25">')]!r})
        for _ in range(30000):
            sys.stdout.write('<!-- ' + 'x' * 100 + ' -->\\n')
        """,
    )
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100, timeout_s=30)
    assert len(run.result.stdout) <= 2_000_000 < 30000 * 100
    assert [s.port for s in run.services] == [22]  # the port before the noise is kept
    assert run.parse_error is not None  # the document was cut off by the output cap


async def test_nmap_gets_a_private_home_and_it_is_removed_afterwards(tmp_path, monkeypatch):
    install_fake(
        tmp_path,
        monkeypatch,
        """
        import os, sys
        sys.stderr.write("HOME=%s\\nCWD=%s\\n" % (os.environ["HOME"], os.getcwd()))
        argv = sys.argv[1:]
        open(argv[argv.index("-oN") + 1], "w").write("x")
        sys.stdout.write("<nmaprun></nmaprun>")
        """,
    )
    monkeypatch.setenv("HOME", "/nonexistent-real-home")
    run = await run_nmap("203.0.113.7", [22], environment="production", pps=100)
    lines = dict(line.split("=", 1) for line in run.result.stderr.split())
    assert lines["HOME"] != "/nonexistent-real-home" and lines["CWD"] == lines["HOME"]
    assert not Path(lines["HOME"]).exists()


# --- version -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Nmap version 7.93 ( https://nmap.org )\\nPlatform: x86_64-pc-linux-gnu\\n", "7.93"),
        ("Nmap version 7.94SVN ( https://nmap.org )\\n", "7.94SVN"),
        ("some other tool 1.2.3\\n", None),
        ("", None),
    ],
)
async def test_version_parses_the_banner(tmp_path, monkeypatch, output, expected):
    install_fake(tmp_path, monkeypatch, f"import sys\nsys.stdout.write('{output}')\n")
    assert await nmap_wrapper.version() == expected


async def test_version_asks_with_dash_dash_version(tmp_path, monkeypatch):
    argv_file = tmp_path / "argv.json"
    install_fake(
        tmp_path,
        monkeypatch,
        f"import json, sys\nopen({str(argv_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n",
    )
    await nmap_wrapper.version()
    assert json.loads(argv_file.read_text()) == ["--version"]


async def test_version_never_raises(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "import sys\nsys.exit(3)\n")
    assert await nmap_wrapper.version() is None

    async def explode(*a, **kw):
        raise OSError("exec failed")

    monkeypatch.setattr(nmap_wrapper, "run_tool", explode)
    assert await nmap_wrapper.version() is None
