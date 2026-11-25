from sentinel_core import scan_options


def test_resolve_defaults_and_known_values():
    assert scan_options.resolve(None) == (5.0, 100)
    assert scan_options.resolve({"speed": "gentle", "depth": "deep"}) == (2.0, 300)
    assert scan_options.resolve({"speed": "bogus", "depth": None}) == (5.0, 100)


def test_recon_profile_defaults_to_light_for_old_or_unknown_values():
    assert scan_options.resolve_recon_profile(None) == "light"
    assert scan_options.resolve_recon_profile({}) == "light"  # scans from before profiles
    assert scan_options.resolve_recon_profile({"recon_profile": "bogus"}) == "light"
    assert scan_options.resolve_recon_profile({"recon_profile": None}) == "light"
    assert scan_options.resolve_recon_profile({"recon_profile": "light"}) == "light"


def test_recon_profile_full_is_only_given_when_asked_for():
    assert scan_options.resolve_recon_profile({"recon_profile": "full"}) == "full"


# --- Active tools ---------------------------------------------------------------


def test_active_tools_lists_only_the_switched_on_ones_in_a_fixed_order():
    assert scan_options.active_tools(None) == []
    assert scan_options.active_tools({}) == []
    assert scan_options.active_tools({"speed": "gentle"}) == []
    assert scan_options.active_tools({"port_scan": True, "dir_bruteforce": True}) == [
        "dir_bruteforce",
        "port_scan",
    ]
    assert scan_options.active_tools({"all_ports": True}) == ["all_ports"]
    # Only a real True counts: a stray string or 1 in stored JSON never switches a tool on.
    assert scan_options.active_tools({"dir_bruteforce": "yes", "port_scan": 1}) == []
    assert scan_options.active_tools({"dir_bruteforce": False}) == []


def test_implemented_tools_are_a_subset_of_the_known_ones():
    assert set(scan_options.IMPLEMENTED_ACTIVE_TOOLS) <= set(scan_options.ACTIVE_TOOL_KEYS)
    assert set(scan_options.ACTIVE_TOOL_LABELS) == set(scan_options.ACTIVE_TOOL_KEYS)


def test_all_three_active_tools_are_implemented_in_this_build():
    assert scan_options.IMPLEMENTED_ACTIVE_TOOLS == ("dir_bruteforce", "port_scan", "all_ports")


def test_resolvers_fall_back_to_the_safe_defaults():
    assert scan_options.resolve_wordlist(None) == "sentinel-core"
    assert scan_options.resolve_wordlist({"wordlist": "bogus"}) == "sentinel-core"
    assert scan_options.resolve_wordlist({"wordlist": "seclists-common"}) == "seclists-common"
    assert scan_options.resolve_target_environment(None) == "production"
    assert scan_options.resolve_target_environment({"target_environment": "x"}) == "production"
    assert scan_options.resolve_target_environment({"target_environment": "staging"}) == "staging"
    assert scan_options.resolve_speed({"speed": "fast"}) == "fast"
    assert scan_options.resolve_speed({"speed": "bogus"}) == "normal"


def test_port_rates_and_the_all_ports_ceiling():
    assert scan_options.PORT_PACKETS_PER_SECOND == {"gentle": 50, "normal": 100, "fast": 200}
    assert scan_options.ALL_PORTS_MAX_PPS == 100


def test_estimate_is_empty_when_no_active_tool_is_on():
    est = scan_options.estimate({"speed": "normal"})
    assert est["dir_bruteforce"] is None
    assert est["port_scan"] is None
    assert est["all_ports"] is None
    assert est["total_seconds"] == 0


def test_estimate_directory_brute_force_is_entries_over_the_request_rate():
    est = scan_options.estimate(
        {"dir_bruteforce": True, "speed": "normal", "recon_profile": "light"}
    )
    d = est["dir_bruteforce"]
    assert d["entries"] == 1500
    assert d["requests_per_second"] == 5.0
    assert d["seconds_per_host"] == 300  # 1500 / 5
    assert d["max_hosts"] == 5
    # 5 hosts x 300 s = 1500 s, under the 1800 s light budget
    assert d["seconds_total"] == 1500
    assert est["total_seconds"] == 1500


def test_estimate_is_capped_by_the_budget():
    est = scan_options.estimate(
        {"dir_bruteforce": True, "speed": "gentle", "recon_profile": "light"}
    )
    d = est["dir_bruteforce"]
    assert d["seconds_per_host"] == 750  # 1500 / 2
    assert d["seconds_total"] == scan_options.DIR_BUDGET_S["light"]  # 5 x 750 > 1800


def test_estimate_one_host_never_runs_longer_than_its_per_host_cap():
    est = scan_options.estimate(
        {
            "dir_bruteforce": True,
            "wordlist": "seclists-common",
            "speed": "gentle",
            "recon_profile": "full",
        }
    )
    d = est["dir_bruteforce"]
    assert scan_options.DIR_HOST_CAP_S["full"] < 4751 / 2
    assert d["seconds_per_host"] == scan_options.DIR_HOST_CAP_S["full"] == 1800
    assert d["seconds_total"] == min(10 * 1800, scan_options.DIR_BUDGET_S["full"])
    assert scan_options.DIR_HOST_CAP_S == {"light": 900, "full": 1800}


def test_estimate_seclists_wordlist_is_bigger():
    est = scan_options.estimate(
        {
            "dir_bruteforce": True,
            "wordlist": "seclists-common",
            "speed": "fast",
            "recon_profile": "full",
        }
    )
    d = est["dir_bruteforce"]
    assert d["entries"] == 4751
    assert d["seconds_per_host"] == int(4751 / 10)


def test_estimate_ports_is_two_passes_of_the_top_1000_per_ip():
    est = scan_options.estimate({"port_scan": True, "speed": "normal", "recon_profile": "light"})
    p = est["port_scan"]
    assert p["packets_per_second"] == 100
    assert p["seconds_per_ip"] == 25  # 1000 x 2 / 100 + 5
    assert p["max_ips"] == 10
    assert p["seconds_total"] == 250


def test_estimate_all_ports_never_goes_faster_than_100_pps():
    est = scan_options.estimate(
        {"port_scan": True, "all_ports": True, "speed": "fast", "recon_profile": "full"}
    )
    a = est["all_ports"]
    assert a["packets_per_second"] == 100  # fast is 200, capped
    assert a["seconds_per_ip"] == 660  # 65535 / 100 + 5, truncated
    assert a["max_ips"] == 3
    assert a["seconds_total"] == min(3 * a["seconds_per_ip"], scan_options.ALL_PORTS_EXTRA_BUDGET_S)
    # all ports is in addition to the top-1000 scan, not instead of it
    assert est["total_seconds"] == est["port_scan"]["seconds_total"] + a["seconds_total"]


def test_estimate_ignores_unknown_values():
    est = scan_options.estimate(
        {"dir_bruteforce": True, "speed": "bogus", "recon_profile": "bogus"}
    )
    assert est["speed"] == "normal"
    assert est["recon_profile"] == "light"
