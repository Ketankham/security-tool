"""dir_hits: the pure rules that turn raw ffuf hits into a short list."""

import random
import re

import pytest
from sentinel_recon.dir_hits import (
    BACKPRESSURE,
    KEEP_STATUSES,
    BackpressureMonitor,
    Baseline,
    baseline_from_response,
    calibration_strings,
    filter_hits,
    normalise_redirect,
)
from sentinel_recon.ffuf_wrapper import FfufHit


def hit(path="x", status=200, words=10, lines=3, redirect="", url=None, length=100):
    return FfufHit(
        path=path,
        status=status,
        length=length,
        words=words,
        lines=lines,
        redirect=redirect,
        url=url if url is not None else f"https://203.0.113.9/{path}",
    )


# --- constants ----------------------------------------------------------------


def test_keep_and_backpressure_sets():
    assert {*range(200, 300), 301, 302, 303, 307, 308, 401, 403, 405, 500} == KEEP_STATUSES
    assert {429, 503} == BACKPRESSURE
    assert not KEEP_STATUSES & BACKPRESSURE
    for status in (404, 400, 410, 304, 501, 502):
        assert status not in KEEP_STATUSES


# --- BackpressureMonitor --------------------------------------------------------


def test_backpressure_stops_after_five_in_a_row():
    m = BackpressureMonitor()
    assert [m.observe(429) for _ in range(4)] == [True] * 4
    assert m.observe(503) is False  # the fifth consecutive (503 counts like 429)
    assert m.stopped and m.reason and "5 in a row" in m.reason
    assert m.observe(200) is False  # stays stopped


def test_a_normal_hit_resets_the_consecutive_count():
    m = BackpressureMonitor()
    for _ in range(4):
        assert m.observe(429)
    assert m.observe(200)
    assert m.consecutive == 0
    for _ in range(4):
        assert m.observe(429)
    assert m.total == 8
    assert not m.stopped


def test_backpressure_stops_after_ten_in_total_even_when_spread_out():
    m = BackpressureMonitor()
    results = []
    for _ in range(10):
        for _ in range(3):
            results.append(m.observe(429))
            if m.stopped:
                break
        if m.stopped:
            break
        m.observe(200)
    assert m.stopped
    assert m.total == 10
    assert results[-1] is False
    assert m.consecutive < 5  # it was the total that tripped it


def test_backpressure_reason_is_none_until_stopped():
    m = BackpressureMonitor()
    m.observe(429)
    assert m.reason is None


# --- baselines and redirects ----------------------------------------------------


def test_baseline_from_response_counts_like_ffuf():
    b = baseline_from_response(200, b"a b c\nd e\n", None, "http://h/x")
    assert b.status == 200
    # ffuf: words = count(" ") + 1, lines = count("\n") + 1
    assert b.words == b"a b c\nd e\n".count(b" ") + 1 == 4
    assert b.lines == 3
    assert baseline_from_response(302, b"", "/login", "http://h/x").redirect == "/login"


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/login", "/login"),
        ("/login?next=/admin123", "/login"),
        ("/login#frag", "/login"),
        ("https://203.0.113.9/login?x=1", "/login"),
        ("//203.0.113.9/login", "/login"),
        ("login", "/login"),
        ("", None),
        ("   ", None),
        ("https://sso.example.org/auth?r=1", "//sso.example.org/auth"),
        ("https://sso.example.org:8443", "//sso.example.org:8443/"),
        ("http://[::1", None),  # unparsable
    ],
)
def test_normalise_redirect(location, expected):
    assert normalise_redirect(location, "https://203.0.113.9/xyz", ()) == expected


def test_normalise_redirect_treats_site_hosts_as_the_site():
    assert normalise_redirect("https://shop.example/login", "https://203.0.113.9/x", ()) == (
        "//shop.example/login"
    )
    assert (
        normalise_redirect("https://shop.example/login", "https://203.0.113.9/x", {"SHOP.example"})
        == "/login"
    )
    # relative target resolves against the directory of the request
    assert normalise_redirect("c", "https://h/a/b", ()) == "/a/c"


# --- filter_hits ----------------------------------------------------------------


def test_catch_all_200_is_dropped_by_the_baseline():
    baselines = [Baseline(200, 12, 1), Baseline(200, 12, 1)]
    hits = [hit(f"p{i}", 200, 12, 1) for i in range(40)] + [hit("real", 200, 300, 40)]
    kept, dropped, catch_all = filter_hits(hits, baselines, entries_count=1000)
    assert [h.path for h in kept] == ["real"]
    assert dropped == {"baseline": 40}
    assert catch_all is False


def test_everything_redirects_to_login_is_dropped_whatever_the_query_or_form():
    baselines = [
        Baseline(
            302,
            1,
            1,
            redirect="/login?next=/sentinelcalabc",
            url="https://203.0.113.9/sentinelcalabc",
        ),
        Baseline(
            302,
            1,
            1,
            redirect="/login?next=/sentinelcaldef",
            url="https://203.0.113.9/sentinelcaldef",
        ),
    ]
    hits = [
        hit("a", 302, 2, 1, redirect="/login?next=/a"),
        hit("b", 301, 5, 2, redirect="https://203.0.113.9/login"),  # different status/size
        hit("c", 307, 5, 2, redirect="login"),  # relative to the root request
        hit("d", 302, 1, 1, redirect="/dashboard"),  # a real redirect (but same shape as baseline!)
        hit("e", 301, 9, 1, redirect="/e/"),  # directory slash redirect
    ]
    kept, dropped, _ = filter_hits(hits, baselines, 100)
    # "d" has the baseline's (status, words, lines) so it is dropped as baseline-equal
    assert [h.path for h in kept] == ["e"]
    assert dropped == {"redirect_baseline": 3, "baseline": 1}


def test_redirect_compare_uses_the_request_url_of_each_hit():
    baselines = [Baseline(302, 1, 1, redirect="/sub/login", url="https://h/sentinelcal")]
    hits = [
        hit("x", 301, 2, 2, redirect="login", url="https://h/sub/x"),  # resolves to /sub/login
        hit("y", 301, 2, 2, redirect="login", url="https://h/y"),  # resolves to /login
    ]
    kept, dropped, _ = filter_hits(hits, baselines, 100)
    assert [h.path for h in kept] == ["y"]
    assert dropped == {"redirect_baseline": 1}


def test_a_redirect_with_no_baseline_redirect_is_kept():
    baselines = [Baseline(404, 3, 1)]
    kept, dropped, _ = filter_hits([hit("a", 302, 1, 1, redirect="/login")], baselines, 100)
    assert len(kept) == 1 and dropped == {}


def test_statuses_outside_the_keep_set_are_dropped_and_counted():
    hits = [
        hit("ok", 200),
        hit("nf", 404),
        hit("bad", 400),
        hit("r1", 429),
        hit("r2", 503),
        hit("auth", 401),
        hit("forbidden", 403),
        hit("method", 405),
        hit("boom", 500),
        hit("nm", 304),
    ]
    kept, dropped, _ = filter_hits(hits, [], 100)
    assert [h.path for h in kept] == ["ok", "auth", "forbidden", "method", "boom"]
    assert dropped == {"status_not_kept": 3, "backpressure": 2}


def test_baseline_equality_needs_all_of_status_words_and_lines():
    baselines = [Baseline(403, 7, 2)]
    hits = [hit("a", 403, 7, 2), hit("b", 403, 7, 3), hit("c", 403, 8, 2), hit("d", 200, 7, 2)]
    kept, dropped, _ = filter_hits(hits, baselines, 100)
    assert [h.path for h in kept] == ["b", "c", "d"]
    assert dropped == {"baseline": 1}


@pytest.mark.parametrize(
    ("entries", "n_hits", "expected"),
    [
        (1000, 300, False),  # exactly 30% is not more than 30%
        (1000, 301, True),
        (100, 50, False),  # floor of 50
        (100, 51, True),
        (4751, 1425, False),
        (4751, 1426, True),
        (10, 3, False),
    ],
)
def test_catch_all_threshold(entries, n_hits, expected):
    hits = [hit(f"p{i}", 200, i + 1, 1) for i in range(n_hits)]
    kept, _, catch_all = filter_hits(hits, [], entries)
    assert len(kept) == n_hits  # kept is returned untouched either way
    assert catch_all is expected


def test_order_is_preserved_and_empty_input_is_fine():
    assert filter_hits([], [], 0) == ([], {}, False)
    hits = [hit("z"), hit("a", words=11), hit("m", words=12)]
    assert [h.path for h in filter_hits(hits, [], 10)[0]] == ["z", "a", "m"]


# --- calibration_strings ----------------------------------------------------------


def test_calibration_strings_shape():
    strings = calibration_strings()
    assert len(strings) == 5
    assert len(set(strings)) == 5
    dirs = [s for s in strings if s.endswith("/")]
    dots = [s for s in strings if s.startswith(".")]
    plain = [s for s in strings if s not in dirs and s not in dots]
    assert len(dirs) == 1 and len(dots) == 1 and len(plain) == 3
    assert sorted(len(s) - len("sentinelcal") for s in plain) == [12, 20, 28]
    assert len(dirs[0]) - len("sentinelcal") - 1 == 20
    assert dots[0].startswith(".sentinelcal")
    for s in plain + dirs:
        assert s.startswith("sentinelcal")
    for s in strings:
        assert re.fullmatch(r"\.?[a-z0-9]+/?", s), s
        assert s.count("/") == (1 if s in dirs else 0)
        assert "admin" not in s and "htaccess" not in s


def test_calibration_strings_are_random_but_seedable():
    assert calibration_strings() != calibration_strings()
    assert calibration_strings(random.Random(7)) == calibration_strings(random.Random(7))
    assert calibration_strings(random.Random(7)) != calibration_strings(random.Random(8))
    assert len(calibration_strings(random.Random(1))) == 5
