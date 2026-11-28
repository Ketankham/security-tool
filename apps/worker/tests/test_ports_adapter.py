"""The port scanning step's own logic, with fake naabu/nmap runners: which
addresses are scanned (and which are refused), the rate, the all-ports double
opt-in, the budget, cancel, a proxy-like host, merging nmap into the rows,
and that nothing secret-looking from nmap reaches the database."""

from __future__ import annotations

import pytest
import sentinel_worker_test_fixture_dir_support as sup
import sentinel_worker_test_fixture_port_support as ps
from sentinel_core import scan_options
from sentinel_core.redact import REDACTED
from sentinel_recon import nmap_wrapper
from sentinel_recon.naabu_wrapper import OpenPort
from sentinel_recon.nmap_wrapper import ScriptOutput
from sentinel_worker_app.cancel import ScanCancelled
from sentinel_worker_app.ports_adapter import host_order, select_ips

BEARER = "Zx9Qk2LmPv7RtW4yUb8N"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"

PUBLIC_1, PUBLIC_2, PUBLIC_3, PUBLIC_4 = "34.120.0.7", "34.120.0.8", "34.120.0.9", "34.120.0.10"


def guard(*hosts: str, rules=None):
    return sup.guard_for(set(hosts) or {"acme.test"}, rules)


# --- Choosing addresses (no database) ------------------------------------------------------


def test_only_in_scope_hosts_count_whether_or_not_they_answer_http():
    recon = ps.recon_ips(
        ("acme.test", [PUBLIC_1]),
        ("api.acme.test", [PUBLIC_2], "in_scope"),
        ("excluded.acme.test", ["34.120.0.50"], "excluded"),
        ("internal.acme.test", ["34.120.0.51"], "private_ip"),
        ("gone.acme.test", [], "unresolved"),
        ("late.acme.test", ["34.120.0.52"], "capped"),
    )
    recon.assets[1].http_probes.clear()  # in scope, but it did not answer HTTP
    selection = select_ips(
        recon, scope_guard=guard("acme.test", "api.acme.test"), allow_private=False, max_ips=10
    )
    assert [p.ip for p in selection.ips] == [PUBLIC_1, PUBLIC_2]
    assert selection.over_cap == [] and selection.refused == []


def test_the_root_domains_addresses_come_first_then_hosts_a_to_z():
    recon = ps.recon_ips(
        ("zeta.acme.test", ["34.120.0.30"]),
        ("acme.test", ["34.120.0.20"]),
        ("alpha.acme.test", ["34.120.0.10"]),
        ("www.acme.test", ["34.120.0.40"]),
        root="acme.test",
    )
    selection = select_ips(recon, scope_guard=sup.guard_for({"acme.test", "*.acme.test"}),
                           allow_private=False, max_ips=10)  # fmt: skip
    assert [p.ip for p in selection.ips] == [
        "34.120.0.20",
        "34.120.0.10",
        "34.120.0.40",
        "34.120.0.30",
    ]
    assert [p.hosts[0] for p in selection.ips] == [
        "acme.test",
        "alpha.acme.test",
        "www.acme.test",
        "zeta.acme.test",
    ]
    assert host_order("acme.test", ["b.acme.test", "acme.test", "a.acme.test"]) == [
        "acme.test",
        "a.acme.test",
        "b.acme.test",
    ]


def test_an_address_shared_by_several_hosts_is_scanned_once_and_keeps_all_their_names():
    recon = ps.recon_ips(
        ("acme.test", [PUBLIC_1]),
        ("app.acme.test", [PUBLIC_1, PUBLIC_2]),
        ("cdn.acme.test", [PUBLIC_2]),
        root="acme.test",
    )
    selection = select_ips(recon, scope_guard=sup.guard_for({"acme.test", "*.acme.test"}),
                           allow_private=False, max_ips=10)  # fmt: skip
    by_ip = {p.ip: p.hosts for p in selection.ips}
    assert by_ip == {
        PUBLIC_1: ("acme.test", "app.acme.test"),
        PUBLIC_2: ("app.acme.test", "cdn.acme.test"),
    }


def test_the_cap_keeps_the_first_addresses_and_reports_the_rest():
    recon = ps.recon_ips(
        ("acme.test", ["34.120.0.1"]),
        *[(f"h{i:02d}.acme.test", [f"34.120.0.{i + 10}"]) for i in range(12)],
        root="acme.test",
    )
    selection = select_ips(recon, scope_guard=sup.guard_for({"acme.test", "*.acme.test"}),
                           allow_private=False, max_ips=10)  # fmt: skip
    assert len(selection.ips) == 10 and len(selection.over_cap) == 3
    assert selection.ips[0].ip == "34.120.0.1"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.5.5.5",
        "10.0.0.5",
        "172.16.9.9",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fd00::5",
        "224.0.0.1",
        "ff02::1",
    ],
)
def test_a_public_name_that_resolves_to_a_non_public_address_is_never_selected(ip):
    recon = ps.recon_ips(("acme.test", [ip]), ("www.acme.test", [PUBLIC_1]), root="acme.test")
    selection = select_ips(recon, scope_guard=guard("acme.test", "www.acme.test"),
                           allow_private=False, max_ips=10)  # fmt: skip
    assert [p.ip for p in selection.ips] == [PUBLIC_1]
    assert selection.refused_ips == 1
    assert any(ip in line and "non-public" in line for line in selection.refused)


def test_a_mixed_host_loses_only_its_private_address():
    recon = ps.recon_ips(("acme.test", [PUBLIC_1, "10.1.2.3"]))
    selection = select_ips(recon, scope_guard=guard("acme.test"), allow_private=False, max_ips=10)
    assert [p.ip for p in selection.ips] == [PUBLIC_1]


def test_private_addresses_are_selected_only_when_the_deployment_allows_them():
    recon = ps.recon_ips(("acme.test", ["127.0.0.1"]))
    allowed = select_ips(recon, scope_guard=guard("acme.test"), allow_private=True, max_ips=10)
    assert [p.ip for p in allowed.ips] == ["127.0.0.1"] and allowed.refused == []


def test_a_host_the_scope_guard_blocks_is_refused_even_when_recon_called_it_in_scope():
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]), ("www.acme.test", [PUBLIC_2]), root="acme.test")
    rules = [sup.rule("host", "www.acme.test")]
    selection = select_ips(recon, scope_guard=sup.guard_for({"acme.test", "www.acme.test"}, rules),
                           allow_private=False, max_ips=10)  # fmt: skip
    assert [p.ip for p in selection.ips] == [PUBLIC_1]
    assert any(line.startswith("www.acme.test:") for line in selection.refused)


def test_something_that_is_not_an_address_is_refused_not_passed_on():
    recon = ps.recon_ips(("acme.test", ["-iL /etc/passwd", "not-an-ip", PUBLIC_1]))
    selection = select_ips(recon, scope_guard=guard("acme.test"), allow_private=False, max_ips=10)
    assert [p.ip for p in selection.ips] == [PUBLIC_1]
    assert len(selection.refused) == 2


# --- The step: what it records ------------------------------------------------------------


async def test_a_light_scan_stores_open_ports_named_from_the_port_number_and_never_runs_nmap(
    db_engine,
):
    naabu = ps.FakeNaabu({PUBLIC_1: [22, 443, 31337]})
    nmap = ps.FakeNmap()
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]), ("www.acme.test", [PUBLIC_1]), root="acme.test")
    result = await ps.run_ports_step(
        db_engine, recon, tools=ps.fake_tools(naabu, nmap), profile="light", seq=5
    )

    assert result.error is None
    assert nmap.calls == []  # Light never runs nmap, even though it is "installed"
    rows = await result.rows()
    assert [(r.port, r.service, r.confidence, r.found_by, r.state) for r in rows] == [
        (22, "ssh", "port_guess", "naabu", "open"),
        (443, "https", "port_guess", "naabu", "open"),
        (31337, None, "port_guess", "naabu", "open"),  # unknown port: no guessed name
    ]
    assert all(r.hosts == ["acme.test", "www.acme.test"] and r.protocol == "tcp" for r in rows)
    assert all(r.product is None and r.scripts == {} and r.cdn is None for r in rows)
    runs = await result.tool_runs()
    assert [(r.seq, r.tool, r.phase, r.status, r.results_count) for r in runs] == [
        (5, "naabu", "recon", "ok", 3)
    ]
    assert all(r.tool_run_id == runs[0].id for r in rows)
    assert result.stats.ips_planned == 1 and result.stats.ips_scanned == 1
    assert result.stats.open_ports == 3 and result.stats.nmap == "skipped"
    assert result.stats.next_seq == 6
    assert result.stats.as_dict() == {
        "ips_planned": 1,
        "ips_scanned": 1,
        "open_ports": 3,
        "all_ports_ips": 0,
        "nmap": "skipped",
        "not_scanned": 0,
        "refused_ips": 0,
        "suspicious_ips": 0,
    }


async def test_the_activity_log_tells_what_was_planned_run_and_found(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [22, 443]})
    recon = ps.recon_ips(
        ("acme.test", [PUBLIC_1]), ("blog.acme.test", [PUBLIC_2]), root="acme.test"
    )
    result = await ps.run_ports_step(db_engine, recon, tools=ps.fake_tools(naabu), speed_pps=100)
    log = result.log
    assert log.has(
        "Port scan of 2 IP(s): top 1,000 TCP ports, connect scan, 100 packets/s, one IP at a "
        "time. Authorised by alice."
    )
    assert any(m.startswith("Running: naabu -host 34.120.0.7 ") for m in log.messages)
    assert f"{PUBLIC_1} (acme.test): 2 open: 22, 443" in log.messages
    assert f"{PUBLIC_2} (blog.acme.test): no open ports" in log.messages
    assert {stage for stage, _l, _m in log.lines} == {"ports"}


async def test_cdn_addresses_keep_the_cdn_name(db_engine):
    naabu = ps.FakeNaabu(
        {PUBLIC_1: [OpenPort(ip=PUBLIC_1, port=443, cdn=True, cdn_name="cloudflare")]}
    )
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu)
    )
    (row,) = await result.rows()
    assert row.cdn == "cloudflare"


async def test_the_same_port_reported_twice_is_one_row(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [443, 443]})
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu)
    )
    assert result.error is None
    assert len(await result.rows()) == 1


async def test_a_shared_address_is_scanned_once(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [80]})
    recon = ps.recon_ips(
        ("acme.test", [PUBLIC_1]), ("shop.acme.test", [PUBLIC_1]), root="acme.test"
    )
    result = await ps.run_ports_step(db_engine, recon, tools=ps.fake_tools(naabu))
    assert naabu.ips == [PUBLIC_1]
    (row,) = await result.rows()
    assert row.hosts == ["acme.test", "shop.acme.test"]


# --- Refusing addresses -------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.0.7", "169.254.169.254", "::1"])
async def test_with_the_address_guard_on_a_public_name_pointing_inside_is_never_scanned(
    db_engine, ip
):
    naabu = ps.FakeNaabu({ip: [22, 80]})
    nmap = ps.FakeNmap()
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [ip])),
        tools=ps.fake_tools(naabu, nmap),
        profile="full",
        allow_private=False,
    )
    assert naabu.calls == [] and nmap.calls == []  # nothing was ever started
    assert await result.rows() == []
    assert result.stats.refused_ips == 1 and result.stats.ips_planned == 0
    assert result.log.has(f"{ip} is a non-public address")
    assert result.log.has("no in-scope public address to scan")


async def test_a_refused_address_does_not_stop_the_public_ones(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [443], "10.0.0.5": [22]})
    recon = ps.recon_ips(
        ("acme.test", ["10.0.0.5"]), ("www.acme.test", [PUBLIC_1]), root="acme.test"
    )
    result = await ps.run_ports_step(
        db_engine, recon, tools=ps.fake_tools(naabu), allow_private=False
    )
    assert naabu.ips == [PUBLIC_1]
    assert [(r.ip, r.port) for r in await result.rows()] == [(PUBLIC_1, 443)]


async def test_hosts_that_are_not_in_scope_are_never_scanned(db_engine):
    naabu = ps.FakeNaabu()
    recon = ps.recon_ips(
        ("acme.test", [PUBLIC_1]),
        ("secret.acme.test", [PUBLIC_2], "excluded"),
        root="acme.test",
    )
    await ps.run_ports_step(db_engine, recon, tools=ps.fake_tools(naabu))
    assert naabu.ips == [PUBLIC_1]


# --- The cap ------------------------------------------------------------------------------


async def test_addresses_over_the_cap_are_listed_not_scanned(db_engine):
    naabu = ps.FakeNaabu()
    recon = ps.recon_ips(
        ("acme.test", ["34.120.0.1"]),
        *[(f"h{i:02d}.acme.test", [f"34.120.0.{i + 10}"]) for i in range(1, 12)],
        root="acme.test",
    )
    result = await ps.run_ports_step(
        db_engine,
        recon,
        tools=ps.fake_tools(naabu),
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )
    cap = scan_options.PORT_MAX_IPS["light"]
    assert len(naabu.calls) == cap == 10
    assert result.stats.not_scanned == 2 and result.stats.ips_planned == 10
    assert result.log.has("2 address(es) not scanned: over the limit of 10 per scan")
    assert result.log.has("(34.120.0.20, 34.120.0.21)")


async def test_the_full_profile_has_a_higher_cap(db_engine):
    recon = ps.recon_ips(
        ("acme.test", ["34.120.0.1"]),
        *[(f"h{i:02d}.acme.test", [f"34.120.0.{i + 10}"]) for i in range(1, 30)],
        root="acme.test",
    )
    naabu = ps.FakeNaabu()
    await ps.run_ports_step(
        db_engine,
        recon,
        tools=ps.fake_tools(naabu),
        profile="full",
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )
    assert len(naabu.calls) == scan_options.PORT_MAX_IPS["full"] == 25


# --- The rate ----------------------------------------------------------------------------


@pytest.mark.parametrize("speed", ["gentle", "normal", "fast"])
async def test_top_ports_run_at_the_speed_settings_packet_rate(db_engine, speed):
    pps = scan_options.PORT_PACKETS_PER_SECOND[speed]
    naabu = ps.FakeNaabu()
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu),
        speed_pps=pps,
    )
    assert [c["pps"] for c in naabu.calls] == [pps] and naabu.calls[0]["all_ports"] is False
    assert result.log.has(f"{pps} packets/s")
    # the command line that was recorded carries the rate
    (run,) = await result.tool_runs()
    assert f"-rate {pps}" in run.command


@pytest.mark.parametrize(("speed", "expected"), [("gentle", 50), ("normal", 100), ("fast", 100)])
async def test_all_ports_never_go_faster_than_the_ceiling(db_engine, speed, expected):
    naabu = ps.FakeNaabu()
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu),
        profile="full",
        options={"port_scan": True, "all_ports": True},
        all_ports_confirmed=True,
        speed_pps=scan_options.PORT_PACKETS_PER_SECOND[speed],
    )
    assert naabu.calls[0]["all_ports"] is True and naabu.calls[0]["pps"] == expected
    assert scan_options.ALL_PORTS_MAX_PPS == 100
    (run,) = await result.tool_runs()
    assert f"-rate {expected} " in run.command and "-p 1-65535" in run.command


async def test_a_silly_rate_from_the_caller_is_clamped_to_the_fastest_setting(db_engine):
    naabu = ps.FakeNaabu()
    await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu),
        speed_pps=100000,
    )
    assert naabu.calls[0]["pps"] == max(scan_options.PORT_PACKETS_PER_SECOND.values())
    naabu2 = ps.FakeNaabu()
    await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu2), speed_pps=0
    )
    assert naabu2.calls[0]["pps"] == 1  # never 0: naabu would refuse to start


# --- All ports needs both opt-ins ---------------------------------------------------------


@pytest.mark.parametrize(
    ("option", "confirmed", "profile", "expected"),
    [
        (True, True, "full", True),
        (True, False, "full", False),  # the option without the separate confirmation
        (False, True, "full", False),  # the confirmation without the option
        (False, False, "full", False),
        (True, True, "light", False),  # all ports is a Full-profile feature
    ],
)
async def test_all_ports_runs_only_with_both_opt_ins(
    db_engine, option, confirmed, profile, expected
):
    naabu = ps.FakeNaabu()
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu),
        profile=profile,
        options={"port_scan": True, "all_ports": option},
        all_ports_confirmed=confirmed,
    )
    assert [c["all_ports"] for c in naabu.calls] == [expected]
    assert result.stats.all_ports_ips == (1 if expected else 0)
    if option and not expected:
        assert result.log.has("All 65,535 ports was requested but")
    if expected:
        assert result.log.has(f"all 65,535 ports on {PUBLIC_1}")


async def test_all_ports_applies_to_the_first_three_addresses_only(db_engine):
    recon = ps.recon_ips(
        ("acme.test", ["34.120.0.1"]),
        *[(f"h{i}.acme.test", [f"34.120.0.{i + 10}"]) for i in range(1, 5)],
        root="acme.test",
    )
    naabu = ps.FakeNaabu()
    result = await ps.run_ports_step(
        db_engine,
        recon,
        tools=ps.fake_tools(naabu),
        profile="full",
        options={"port_scan": True, "all_ports": True},
        all_ports_confirmed=True,
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )
    assert [c["all_ports"] for c in naabu.calls] == [True, True, True, False, False]
    assert [c["pps"] for c in naabu.calls] == [100, 100, 100, 100, 100]
    assert result.stats.all_ports_ips == 3
    assert result.log.has("applies to the first 3 address(es) only")
    assert result.log.has("all 65,535 ports on 34.120.0.1, 34.120.0.11, 34.120.0.12")


async def test_all_ports_gets_the_extra_time_budget(db_engine):
    # with ALL_PORTS_EXTRA_BUDGET_S the whole step may run 45 + 30 minutes
    clock = ps.FakeClock()
    naabu = ps.FakeNaabu(on_call=lambda _ip: clock.advance(2900))
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]), ("b.acme.test", [PUBLIC_2]), root="acme.test")
    result = await ps.run_ports_step(
        db_engine,
        recon,
        tools=ps.fake_tools(naabu),
        profile="full",
        options={"port_scan": True, "all_ports": True},
        all_ports_confirmed=True,
        clock=clock,
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )
    # 2900 s used by the first address: above the 2700 s Full budget, below 4500 s
    assert len(naabu.calls) == 2
    assert result.stats.not_scanned == 0


# --- Time budget, cancel -------------------------------------------------------------------


async def test_the_time_budget_stops_the_step_and_names_what_was_not_scanned(db_engine):
    clock = ps.FakeClock()
    naabu = ps.FakeNaabu({PUBLIC_1: [80]}, on_call=lambda _ip: clock.advance(700))
    recon = ps.recon_ips(
        ("acme.test", [PUBLIC_1]),
        ("b.acme.test", [PUBLIC_2]),
        ("c.acme.test", [PUBLIC_3]),
        root="acme.test",
    )
    result = await ps.run_ports_step(
        db_engine,
        recon,
        tools=ps.fake_tools(naabu),
        clock=clock,
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )
    assert naabu.ips == [PUBLIC_1, PUBLIC_2]  # 1,200 s budget: the third has no time left
    assert result.log.has(f"Not scanned: {PUBLIC_3} (time budget).")
    assert result.stats.not_scanned == 1 and result.stats.ips_scanned == 2
    scan = await result.scan()
    assert scan.is_degraded and any("ran out of time" in r for r in scan.degraded_reasons)
    assert len(await result.rows()) == 1  # what was found before the budget ran out is kept


async def test_the_tools_timeout_never_exceeds_the_time_left(db_engine):
    naabu = ps.FakeNaabu()
    await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu),
        budget_s=100,
    )
    assert naabu.calls[0]["timeout_s"] <= 100


async def test_a_cancel_between_addresses_stops_before_the_next_one_and_keeps_the_first(db_engine):
    cancel = sup.FakeCancel()

    def press(ip: str) -> None:
        if ip == PUBLIC_1:
            cancel.by = "dana"

    naabu = ps.FakeNaabu({PUBLIC_1: [443]}, on_call=press)
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]), ("b.acme.test", [PUBLIC_2]), root="acme.test")
    result = await ps.run_ports_step(
        db_engine, recon, tools=ps.fake_tools(naabu), cancel=cancel,
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )  # fmt: skip
    assert isinstance(result.error, ScanCancelled) and result.error.by == "dana"
    assert naabu.ips == [PUBLIC_1]  # the second address was never touched
    assert [(r.ip, r.port) for r in await result.rows()] == [(PUBLIC_1, 443)]


async def test_a_cancel_inside_naabu_is_recorded_and_ends_the_step(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [443]}, behaviour={PUBLIC_1: "cancel"})
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu)
    )
    assert isinstance(result.error, ScanCancelled) and result.error.by == "dana"
    (run,) = await result.tool_runs()
    assert (run.tool, run.status, run.skip_reason) == ("naabu", "cancelled", "Cancelled by dana")
    assert len(await result.rows()) == 1  # what it found so far is kept


async def test_the_cancel_check_given_to_naabu_is_the_watch(db_engine):
    seen = []

    class Naabu(ps.FakeNaabu):
        async def __call__(self, ip, *, cancel_check=None, **kwargs):
            seen.append(cancel_check)
            return await super().__call__(ip, cancel_check=cancel_check, **kwargs)

    cancel = sup.FakeCancel()
    await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(Naabu()),
        cancel=cancel,
    )
    assert seen == [cancel.requested]


# --- Things going wrong ------------------------------------------------------------------


async def test_a_naabu_failure_on_one_address_is_logged_and_the_next_address_continues(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_2: [22]}, behaviour={PUBLIC_1: "fail"})
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]), ("b.acme.test", [PUBLIC_2]), root="acme.test")
    result = await ps.run_ports_step(
        db_engine,
        recon,
        tools=ps.fake_tools(naabu),
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )
    assert naabu.ips == [PUBLIC_1, PUBLIC_2]
    assert [(r.ip, r.port) for r in await result.rows()] == [(PUBLIC_2, 22)]
    runs = await result.tool_runs()
    assert [(r.tool, r.status) for r in runs] == [("naabu", "failed"), ("naabu", "ok")]
    scan = await result.scan()
    assert scan.is_degraded and any(
        "naabu failed on 34.120.0.7" in r and "exited with code 2" in r
        for r in scan.degraded_reasons
    )
    assert any(level == "warn" and "naabu failed" in m for _s, level, m in result.log.lines)


async def test_a_naabu_timeout_keeps_the_partial_results_and_says_so(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [22]}, behaviour={PUBLIC_1: "timeout"})
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu)
    )
    (run,) = await result.tool_runs()
    assert run.status == "timed_out"
    assert len(await result.rows()) == 1
    scan = await result.scan()
    assert any("results are partial" in r for r in scan.degraded_reasons)


async def test_naabu_not_installed_skips_the_whole_step_with_a_warning(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [22]})
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu, naabu_installed=False),
    )
    assert result.error is None and naabu.calls == []
    assert await result.rows() == []
    (run,) = await result.tool_runs()
    assert (run.tool, run.status) == ("naabu", "not_installed")
    scan = await result.scan()
    assert scan.is_degraded and any("naabu is not installed" in r for r in scan.degraded_reasons)
    assert result.stats.ips_scanned == 0 and result.stats.not_scanned == 1


async def test_a_proxy_like_address_keeps_its_rows_warns_and_skips_nmap(db_engine):
    naabu = ps.FakeNaabu(behaviour={PUBLIC_1: "suspicious"})
    nmap = ps.FakeNmap()
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )
    assert nmap.calls == []
    assert len(await result.rows()) == 150  # stored, but...
    assert result.stats.suspicious_ips == 1
    scan = await result.scan()
    assert scan.is_degraded and any("appear open everywhere" in r for r in scan.degraded_reasons)
    assert any(
        level == "warn" and "ports appear open everywhere (firewall/proxy?)" in m
        for _s, level, m in result.log.lines
    )
    (run,) = await result.tool_runs()
    assert run.skip_reason == "ports appear open everywhere (firewall/proxy?)"
    assert run.status == "ok"


# --- nmap ---------------------------------------------------------------------------------


def _ssh() -> nmap_wrapper.ServiceInfo:
    return ps.service(
        22,
        "ssh",
        product="OpenSSH",
        version="8.9p1 Ubuntu 3ubuntu0.4",
        extra_info="Ubuntu Linux; protocol 2.0",
        scripts=(ScriptOutput(id="ssh-hostkey", output="256 3b:a1 (ECDSA)"),),
    )


async def test_nmap_results_update_the_rows_naabu_made(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [22, 80, 443, 3306, 8080, 9999]})
    nmap = ps.FakeNmap(
        {
            PUBLIC_1: [
                _ssh(),
                ps.service(80, "http", product="nginx", version="1.24.0"),
                ps.service(443, "http", product="nginx", tunnel="ssl"),
                ps.service(3306, "mysql", state="closed", method="table"),
                ps.service(8080, "http-proxy", method="table", confidence=3),
                ps.service(9999, "unknown", method="table", confidence=3),
            ]
        }
    )
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]))
    result = await ps.run_ports_step(
        db_engine, recon, tools=ps.fake_tools(naabu, nmap), profile="full", seq=3
    )

    assert result.error is None
    assert nmap.calls == [
        {
            "ip": PUBLIC_1,
            "ports": [22, 80, 443, 3306, 8080, 9999],
            "environment": "production",
            "pps": 100,
            "timeout_s": nmap.calls[0]["timeout_s"],
        }
    ]
    assert nmap.calls[0]["timeout_s"] <= nmap_wrapper.DEFAULT_TIMEOUT_S
    rows = await result.by_port()
    ssh = rows[(PUBLIC_1, 22)]
    assert (ssh.service, ssh.product, ssh.version) == ("ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.4")
    assert (ssh.extra_info, ssh.confidence, ssh.found_by) == (
        "Ubuntu Linux; protocol 2.0",
        "detected",
        "nmap",
    )
    assert ssh.scripts == {"ssh-hostkey": "256 3b:a1 (ECDSA)"}
    assert rows[(PUBLIC_1, 80)].confidence == "detected"
    # naabu's row for a port nmap reports closed is kept, with its state updated
    closed = rows[(PUBLIC_1, 3306)]
    assert closed.state == "closed" and closed.confidence == "port_guess"
    assert closed.found_by == "naabu" and closed.service == "mysql"
    # nmap only guessed from its own port table: still an unverified guess
    guess = rows[(PUBLIC_1, 8080)]
    assert (guess.service, guess.confidence, guess.found_by) == ("http-proxy", "port_guess", "nmap")
    unknown = rows[(PUBLIC_1, 9999)]
    assert unknown.service is None and unknown.confidence == "port_guess"
    assert len(rows) == 6  # nothing deleted, nothing duplicated

    runs = await result.tool_runs()
    assert [(r.seq, r.tool, r.status, r.version) for r in runs] == [
        (3, "naabu", "ok", "v2.7.0"),
        (4, "nmap", "ok", "7.93"),
    ]
    nmap_run = runs[1]
    assert nmap_run.extra_output == "Nmap scan report\n"
    assert nmap_run.extra_output_label == "nmap normal output (-oN)"
    assert ssh.tool_run_id == nmap_run.id
    assert result.stats.nmap == "ran" and result.stats.next_seq == 5
    assert result.log.has(f"{PUBLIC_1} (acme.test): nmap identified 3 of 6 service(s)")
    assert any(m.startswith("Running: nmap ") for m in result.log.messages)


async def test_nmap_gets_the_staging_script_set_only_for_staging(db_engine):
    for environment, expected in (("staging", "staging"), ("production", "production")):
        nmap = ps.FakeNmap({PUBLIC_1: [ps.service(22, "ssh")]})
        await ps.run_ports_step(
            db_engine,
            ps.recon_ips(("acme.test", [PUBLIC_1])),
            tools=ps.fake_tools(ps.FakeNaabu({PUBLIC_1: [22]}), nmap),
            profile="full",
            environment=environment,
        )
        assert nmap.calls[0]["environment"] == expected


async def test_without_nmap_the_full_profile_notes_it_once_and_names_services_from_port_numbers(
    db_engine,
):
    naabu = ps.FakeNaabu({PUBLIC_1: [22], PUBLIC_2: [443]})
    nmap = ps.FakeNmap()
    recon = ps.recon_ips(("acme.test", [PUBLIC_1]), ("b.acme.test", [PUBLIC_2]), root="acme.test")
    result = await ps.run_ports_step(
        db_engine, recon, tools=ps.fake_tools(naabu, nmap, nmap_installed=False), profile="full",
        guard=sup.guard_for({"acme.test", "*.acme.test"}),
    )  # fmt: skip
    note = "nmap not installed — services named from port numbers (unverified)"
    assert result.log.messages.count(note) == 1
    assert nmap.calls == []
    runs = await result.tool_runs()
    assert [(r.tool, r.status, r.skip_reason) for r in runs] == [
        ("nmap", "skipped", note),
        ("naabu", "ok", None),
        ("naabu", "ok", None),
    ]
    rows = await result.rows()
    assert {r.service for r in rows} == {"ssh", "https"}
    assert all(r.confidence == "port_guess" for r in rows)
    assert result.stats.nmap == "not_installed"
    scan = await result.scan()
    assert not any("nmap" in r for r in scan.degraded_reasons)  # a note, not a failure


async def test_an_address_with_more_than_50_open_ports_skips_nmap_with_a_record(db_engine):
    ports = list(range(2000, 2051))  # 51 ports
    naabu = ps.FakeNaabu({PUBLIC_1: ports})
    nmap = ps.FakeNmap()
    result = await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )
    assert nmap.calls == []
    runs = await result.tool_runs()
    assert [(r.tool, r.status) for r in runs] == [("naabu", "ok"), ("nmap", "skipped")]
    assert "more than 50 open ports" in (runs[1].skip_reason or "")
    assert result.stats.nmap == "skipped" and len(await result.rows()) == 51


async def test_nmap_is_not_started_without_open_ports(db_engine):
    nmap = ps.FakeNmap()
    await ps.run_ports_step(
        db_engine,
        ps.recon_ips(("acme.test", [PUBLIC_1])),
        tools=ps.fake_tools(ps.FakeNaabu(), nmap),
        profile="full",
    )
    assert nmap.calls == []


async def test_nmap_output_that_cannot_be_read_keeps_naabus_rows_and_degrades(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [22]})
    nmap = ps.FakeNmap(behaviour={PUBLIC_1: "fail"})
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )  # fmt: skip
    (row,) = await result.rows()
    assert row.confidence == "port_guess" and row.service == "ssh"
    runs = await result.tool_runs()
    assert runs[1].tool == "nmap" and runs[1].status == "failed"
    scan = await result.scan()
    assert any("nmap could not be read" in r for r in scan.degraded_reasons)


async def test_a_cancel_inside_nmap_ends_the_step(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [22]})
    nmap = ps.FakeNmap({PUBLIC_1: [_ssh()]}, behaviour={PUBLIC_1: "cancel"})
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )  # fmt: skip
    assert isinstance(result.error, ScanCancelled)
    runs = await result.tool_runs()
    assert [(r.tool, r.status) for r in runs] == [("naabu", "ok"), ("nmap", "cancelled")]


async def test_a_web_service_on_an_unusual_port_becomes_a_crawl_start_page(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [80, 443, 8080, 8443, 3000, 22]})
    nmap = ps.FakeNmap(
        {
            PUBLIC_1: [
                ps.service(80, "http"),
                ps.service(443, "http", tunnel="ssl"),
                ps.service(8080, "http-proxy"),
                ps.service(8443, "http", tunnel="ssl"),
                ps.service(3000, "http", method="table"),  # only nmap's port-table guess
                ps.service(22, "ssh"),
            ]
        }
    )
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )  # fmt: skip
    assert result.stats.web_seeds == ["http://acme.test:8080/", "https://acme.test:8443/"]


async def test_at_most_five_web_services_become_start_pages(db_engine):
    ports = list(range(8001, 8011))
    naabu = ps.FakeNaabu({PUBLIC_1: ports})
    nmap = ps.FakeNmap({PUBLIC_1: [ps.service(p, "http") for p in ports]})
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )  # fmt: skip
    assert len(result.stats.web_seeds) == 5


# --- Nothing secret-looking from nmap reaches the database ---------------------------------


async def test_secret_looking_nmap_output_is_redacted_before_it_is_stored(db_engine):
    naabu = ps.FakeNaabu({PUBLIC_1: [8080]})
    leaky = ps.service(
        8080,
        "http-proxy",
        product=f"proxy Authorization: Bearer {BEARER}",
        extra_info=f"token {JWT}",
        scripts=(
            ScriptOutput(id="banner", output=f"220 ready\nAuthorization: Bearer {BEARER}\n{JWT}"),
        ),
    )
    nmap = ps.FakeNmap(
        {PUBLIC_1: [leaky]},
        normal_output=f"PORT 8080\n|_banner: Authorization: Bearer {BEARER}\n{JWT}\n",
    )
    result = await ps.run_ports_step(
        db_engine, ps.recon_ips(("acme.test", [PUBLIC_1])), tools=ps.fake_tools(naabu, nmap),
        profile="full",
    )  # fmt: skip
    stored = await sup.everything_stored(db_engine)
    assert BEARER not in stored and JWT not in stored
    (row,) = await result.rows()
    assert REDACTED in row.scripts["banner"]
    assert row.scripts["banner"].startswith("220 ready")  # the harmless part survives
    runs = await result.tool_runs()
    assert REDACTED in runs[1].extra_output and BEARER not in runs[1].extra_output
