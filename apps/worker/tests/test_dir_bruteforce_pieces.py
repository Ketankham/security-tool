"""The small decisions inside the directory brute force step, without a
network: which hosts, which paths may be sent, what ffuf is pinned to."""

from __future__ import annotations

import sentinel_worker_test_fixture_dir_support as sup
from sentinel_core.scope_guard import DestructiveActionGuard
from sentinel_recon import DiscoveredAsset, HttpProbeResult, ReconResult, wordlists
from sentinel_worker_app import dir_bruteforce_adapter as adapter
from sentinel_worker_app.dir_bruteforce_adapter import (
    DirStats,
    HostPlan,
    _pick_crawl_seeds,
    _Row,
    allowed_paths,
    host_order,
    select_hosts,
)


def _asset(host, url, ips=("93.184.216.34",), status=200) -> DiscoveredAsset:
    return DiscoveredAsset(
        host=host,
        source="subfinder",
        ips=list(ips),
        http_probes=[HttpProbeResult(url=url, status_code=status, title=None, server=None)],
    )


def _recon(*assets, root="acme.test") -> ReconResult:
    return ReconResult(
        root_domain=root, assets=list(assets), tool_availability={}, wildcard_dns_suspected=False
    )


GUARD = sup.guard_for({"acme.test", "*.acme.test"})


# --- hosts ---------------------------------------------------------------------


def test_hosts_are_root_then_www_then_alphabetical():
    assert host_order(
        "acme.test", ["zeta.acme.test", "www.acme.test", "acme.test", "api.acme.test"]
    ) == [
        "acme.test",
        "www.acme.test",
        "api.acme.test",
        "zeta.acme.test",
    ]
    assert host_order("acme.test", ["b.acme.test", "a.acme.test"]) == ["a.acme.test", "b.acme.test"]


def test_select_hosts_takes_live_in_scope_hosts_in_order_and_caps_them():
    recon = _recon(
        _asset("zed.acme.test", "https://zed.acme.test"),
        _asset("www.acme.test", "https://www.acme.test"),
        _asset("acme.test", "https://acme.test"),
        _asset("api.acme.test", "https://api.acme.test"),
        _asset("dead.acme.test", "https://dead.acme.test", status=None),
    )
    hosts, skipped, over = select_hosts(recon, scope_guard=GUARD, allow_private=False, max_hosts=3)
    assert [h.host for h in hosts] == ["acme.test", "www.acme.test", "api.acme.test"]
    assert over == ["zed.acme.test"]
    assert skipped == []


def test_a_host_the_scope_guard_blocks_is_skipped_with_the_reason():
    guard = sup.guard_for({"acme.test", "*.acme.test"}, [sup.rule("host", "admin.acme.test")])
    recon = _recon(
        _asset("acme.test", "https://acme.test"),
        _asset("admin.acme.test", "https://admin.acme.test"),
    )
    hosts, skipped, _ = select_hosts(recon, scope_guard=guard, allow_private=False, max_hosts=5)
    assert [h.host for h in hosts] == ["acme.test"]
    assert len(skipped) == 1 and skipped[0].startswith("admin.acme.test: ")
    # Only /app/ is in scope, so the front page itself is not: nothing runs.
    only_app = sup.guard_for({"acme.test"}, [sup.rule("path_prefix", "/app/", "include")])
    hosts, skipped, _ = select_hosts(
        _recon(_asset("acme.test", "https://acme.test")),
        scope_guard=only_app,
        allow_private=False,
        max_hosts=5,
    )
    assert hosts == [] and skipped


def test_a_non_public_address_skips_the_host_unless_private_is_allowed():
    recon = _recon(
        _asset("acme.test", "https://acme.test", ips=("10.0.0.5",)),
        _asset("api.acme.test", "https://api.acme.test", ips=("93.184.216.34", "127.0.0.1")),
        _asset("ok.acme.test", "https://ok.acme.test"),
    )
    hosts, skipped, _ = select_hosts(recon, scope_guard=GUARD, allow_private=False, max_hosts=5)
    assert [h.host for h in hosts] == ["ok.acme.test"]
    assert len(skipped) == 2 and all("non-public address" in s for s in skipped)
    allowed, _, _ = select_hosts(recon, scope_guard=GUARD, allow_private=True, max_hosts=5)
    assert [h.host for h in allowed] == ["acme.test", "api.acme.test", "ok.acme.test"]


def test_a_host_without_an_address_or_probe_is_not_run():
    recon = _recon(_asset("acme.test", "https://acme.test", ips=()))
    hosts, skipped, _ = select_hosts(recon, scope_guard=GUARD, allow_private=False, max_hosts=5)
    assert hosts == [] and "no address" in skipped[0]


def test_pinning_uses_the_recon_ip_with_the_real_name_in_host_and_sni():
    recon = _recon(
        _asset("acme.test", "https://acme.test"),
        _asset("alt.acme.test", "https://alt.acme.test:8443", ips=("93.184.216.35",)),
        _asset("plain.acme.test", "http://plain.acme.test"),
        _asset("odd.acme.test", "http://odd.acme.test:8080", ips=("93.184.216.36",)),
        _asset("v6.acme.test", "https://v6.acme.test", ips=("2606:2800:220:1::1",)),
    )
    hosts, _, _ = select_hosts(recon, scope_guard=GUARD, allow_private=False, max_hosts=9)
    by = {h.host: h for h in hosts}
    assert by["acme.test"].pinned_base == "https://93.184.216.34"  # default port left out
    assert by["acme.test"].host_header == "acme.test" and by["acme.test"].sni == "acme.test"
    assert by["alt.acme.test"].pinned_base == "https://93.184.216.35:8443"
    assert by["alt.acme.test"].host_header == "alt.acme.test:8443"
    assert by["alt.acme.test"].sni == "alt.acme.test"
    assert by["plain.acme.test"].pinned_base == "http://93.184.216.34"
    assert by["plain.acme.test"].sni is None  # plain http: no SNI
    assert by["odd.acme.test"].pinned_base == "http://93.184.216.36:8080"
    assert by["odd.acme.test"].host_header == "odd.acme.test:8080"
    assert by["v6.acme.test"].pinned_base == "https://[2606:2800:220:1::1]"
    assert by["acme.test"].origin == "https://acme.test"  # the origin is never the IP
    assert by["alt.acme.test"].origin == "https://alt.acme.test:8443"


def test_no_sni_for_an_ip_literal_host():
    plan = HostPlan(
        host="127.0.0.1",
        origin="https://127.0.0.1",
        scheme="https",
        host_header="127.0.0.1",
        port=443,
        ip="127.0.0.1",
        ips=("127.0.0.1",),
    )
    assert plan.sni is None


# --- what may be sent ----------------------------------------------------------


PATHS = [
    ".env",
    ".git/HEAD",
    "admin",
    "admin/",
    "admin/login.php",
    "administrator/",
    "api/v1/",
    "private/data",
    "backup/old.zip",
    "user/logout",
    "items/delete",
]


def test_path_prefix_excludes_remove_every_path_below_them():
    guard = sup.guard_for({"acme.test"}, [sup.rule("path_prefix", "/admin")])
    ok, by_scope, by_screen = allowed_paths(PATHS, origin="https://acme.test", scope_guard=guard)
    # a prefix rule is a string prefix: /administrator is under /admin too
    assert by_scope == ["admin", "admin/", "admin/login.php", "administrator/"]
    assert "admin" not in ok and ".env" in ok and "private/data" in ok
    # the destructive-action screen is a separate, additional gate
    assert by_screen == ["user/logout", "items/delete"]
    assert not {"user/logout", "items/delete"} & set(ok)


def test_path_regex_excludes_and_include_rules_are_honoured():
    guard = sup.guard_for({"acme.test"}, [sup.rule("path_regex", r"^/(private|backup)/")])
    ok, by_scope, _ = allowed_paths(PATHS, origin="https://acme.test", scope_guard=guard)
    assert by_scope == ["private/data", "backup/old.zip"]
    only_api = sup.guard_for({"acme.test"}, [sup.rule("path_prefix", "/api/", "include")])
    ok, by_scope, _ = allowed_paths(PATHS, origin="https://acme.test", scope_guard=only_api)
    assert ok == ["api/v1/"]


def test_calibration_strings_go_through_the_same_gate():
    guard = sup.guard_for({"acme.test"}, [sup.rule("path_prefix", "/sentinelcal")])
    cal, by_scope, _ = allowed_paths(
        adapter.dh.calibration_strings(), origin="https://acme.test", scope_guard=guard
    )
    # four of the five start with "sentinelcal"; only the dotfile one is left
    assert len(cal) == 1 and cal[0].startswith(".sentinelcal")
    assert len(by_scope) == 4


def test_an_unverified_target_allows_nothing():
    from sentinel_core.scope_guard import ScopeGuard

    guard = ScopeGuard(allowed_hosts={"acme.test"}, target_ownership_verified=False)
    ok, by_scope, _ = allowed_paths(PATHS, origin="https://acme.test", scope_guard=guard)
    assert ok == [] and len(by_scope) == len(PATHS)


def test_the_real_wordlists_split_cleanly_into_get_paths_and_archives():
    for name in ("sentinel-core", "seclists-common"):
        wl = wordlists.load(name)
        if wl is None:
            continue
        archives = [e.path for e in wl.entries if wordlists.is_archive(e.path)]
        get_paths = [e.path for e in wl.entries if not wordlists.is_archive(e.path)]
        assert not set(archives) & set(get_paths)
        assert len(archives) + len(get_paths) == len(wl.entries)
        assert not any(p.lower().endswith(wordlists.ARCHIVE_SUFFIXES) for p in get_paths)
    core = wordlists.load("sentinel-core")
    assert core is not None
    assert any(wordlists.is_archive(e.path) for e in core.entries)  # there is a HEAD pass to do
    guard = DestructiveActionGuard()
    # none of the shipped entries trips the destructive screen, so none is silently dropped
    assert not [
        e.path
        for e in core.entries
        if guard.check(method="GET", url=f"https://acme.test/{e.path}").is_suspect
    ]


# --- crawl seeds ---------------------------------------------------------------


def _plan() -> HostPlan:
    return HostPlan(
        host="acme.test",
        origin="https://acme.test",
        scheme="https",
        host_header="acme.test",
        port=443,
        ip="93.184.216.34",
        ips=("93.184.216.34",),
    )


def _row(path, status=200, ctype="text/html", redirect=None, verdict="found", method="GET"):
    return _Row(
        entry=wordlists.Entry("admin", path),
        method=method,
        status=status,
        length=1,
        words=1,
        lines=1,
        content_type=ctype,
        redirect=redirect,
        verdict=verdict,
    )


def test_crawl_seeds_are_html_pages_and_same_site_redirects_only():
    rows = [
        _row("admin/"),  # HTML page: a seed
        _row("portal", status=302, ctype="text/html", redirect="/portal/"),  # same-site redirect
        _row("away", status=302, redirect="https://elsewhere.example/x"),  # leaves the site
        _row("data.json", ctype="application/json"),  # not a page
        _row(".env", ctype="text/html"),  # a secret path is never offered to the crawler
        _row(".git/HEAD", ctype="text/html", verdict="confirmed"),
        _row("old.zip", ctype="text/html", method="HEAD"),
        _row("denied", status=403),
    ]
    stats = DirStats()
    _pick_crawl_seeds(rows, plan=_plan(), scope_guard=sup.guard_for({"acme.test"}), stats=stats)
    assert stats.path_seeds == ["https://acme.test/admin/", "https://acme.test/portal"]
    assert [r.entry.path for r in rows if r.crawl_seed] == ["admin/", "portal"]


def test_crawl_seeds_respect_scope_and_the_cap():
    guard = sup.guard_for({"acme.test"}, [sup.rule("path_prefix", "/private")])
    rows = [_row("private/"), *[_row(f"page{i}/") for i in range(40)]]
    stats = DirStats()
    _pick_crawl_seeds(rows, plan=_plan(), scope_guard=guard, stats=stats)
    assert len(stats.path_seeds) == adapter.MAX_CRAWL_SEEDS == 20
    assert "https://acme.test/private/" not in stats.path_seeds
    # the cap is for the whole step: a second host adds nothing more
    more = [_row("extra/")]
    _pick_crawl_seeds(more, plan=_plan(), scope_guard=guard, stats=stats)
    assert not more[0].crawl_seed and len(stats.path_seeds) == 20


# --- stats ---------------------------------------------------------------------


def test_stats_have_the_keys_the_recon_phase_records():
    keys = set(DirStats().as_dict())
    assert {
        "hosts_planned",
        "hosts_run",
        "entries",
        "entries_removed_by_scope",
        "wordlist",
        "wordlist_sha256",
        "hits",
        "confirmed",
        "stopped_hosts",
        "not_run_hosts",
    } <= keys


def test_the_origin_is_spelled_without_a_default_port_so_steps_agree_on_it():
    recon = _recon(
        _asset("acme.test", "http://acme.test:80"),
        _asset("api.acme.test", "https://api.acme.test:443"),
        _asset("odd.acme.test", "https://odd.acme.test:8443"),
        _asset("v6.acme.test", "http://[2606:2800:220:1::1]:80", ips=("2606:2800:220:1::1",)),
    )
    guard = sup.guard_for({"acme.test", "*.acme.test", "2606:2800:220:1::1"})
    hosts, _, _ = select_hosts(recon, scope_guard=guard, allow_private=False, max_hosts=9)
    by = {h.host: h for h in hosts}
    assert (
        by["acme.test"].origin == "http://acme.test" and by["acme.test"].host_header == "acme.test"
    )
    assert by["api.acme.test"].origin == "https://api.acme.test"
    assert by["odd.acme.test"].origin == "https://odd.acme.test:8443"
    assert by["odd.acme.test"].host_header == "odd.acme.test:8443"
    assert by["v6.acme.test"].origin == "http://[2606:2800:220:1::1]"
