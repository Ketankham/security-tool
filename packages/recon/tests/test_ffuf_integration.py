"""The real ffuf binary (skipped when it is not on PATH) against tiny local
servers on 127.0.0.1, driven through build_args / run_ffuf / filter_hits exactly
as the worker will. Nothing here talks to any other host."""

import http.client
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sentinel_core.http_engine import USER_AGENT
from sentinel_recon.dir_hits import (
    BackpressureMonitor,
    Baseline,
    baseline_from_response,
    calibration_strings,
    filter_hits,
)
from sentinel_recon.ffuf_wrapper import FfufRun, build_args, run_ffuf

pytestmark = pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf is not installed")

Response = tuple[int, dict[str, str], bytes]


@dataclass
class Site:
    port: int
    log: list[tuple[float, str, str, dict[str, str]]] = field(default_factory=list)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def paths(self, since: int = 0) -> list[str]:
        return [path for _, _, path, _ in self.log[since:]]


@pytest.fixture
def serve():
    servers: list[ThreadingHTTPServer] = []

    def start(respond: Callable[[str, int], Response]) -> Site:
        site = Site(port=0)
        counter = {"n": 0}
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                with lock:
                    counter["n"] += 1
                    n = counter["n"]
                    site.log.append(
                        (time.monotonic(), self.command, self.path, dict(self.headers.items()))
                    )
                status, headers, body = respond(self.path, n)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_HEAD = do_GET  # noqa: N815

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        site.port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return site

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


REAL = [".env", ".git/HEAD", "admin", "config.json", "robots.txt"]


def wordlist(real: list[str] = REAL, fillers: int = 120) -> list[str]:
    entries = [f"page{i}" for i in range(fillers)]
    for i, path in enumerate(real):
        entries.insert(7 + i * 17, path)
    return entries


def normal_site(path: str, n: int) -> Response:
    if path == "/.env":
        return 200, {"Content-Type": "text/plain"}, b"DB_HOST=db\nDB_PASSWORD=hunter2secret\n"
    if path == "/.git/HEAD":
        return 200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n"
    if path == "/admin":
        return 301, {"Location": "/admin/"}, b""
    if path == "/config.json":
        return 403, {"Content-Type": "text/plain"}, b"forbidden by policy"
    if path == "/robots.txt":
        return 200, {"Content-Type": "text/plain"}, b"User-agent: *\nDisallow: /private/\n"
    return 404, {"Content-Type": "text/html"}, b"<html><body>Nothing here, sorry</body></html>"


def catch_all_site(path: str, n: int) -> Response:
    return 200, {"Content-Type": "text/html"}, f"<html>Welcome to {path}!</html>".encode()


def redirect_all_site(path: str, n: int) -> Response:
    if path.split("?")[0] == "/login":
        return 200, {"Content-Type": "text/html"}, b"<html>Please sign in</html>"
    return 302, {"Location": f"/login?next={path}"}, b""


def always_429(path: str, n: int) -> Response:
    return 429, {"Retry-After": "30"}, b"slow down"


def get_baselines(site: Site, cal: list[str]) -> list[Baseline]:
    """What a worker does through its HttpEngine: GET two calibration paths."""
    out = []
    for path in cal[:2]:
        conn = http.client.HTTPConnection("127.0.0.1", site.port, timeout=10)
        conn.request("GET", "/" + path)
        resp = conn.getresponse()
        body = resp.read()
        out.append(
            baseline_from_response(
                resp.status, body, resp.getheader("Location"), f"{site.base}/{path}"
            )
        )
        conn.close()
    return out


@dataclass
class Outcome:
    run: FfufRun
    kept: list
    dropped: dict
    catch_all: bool
    since: int  # index into the site log where ffuf's requests start
    cal: list[str]
    entries: list[str]
    monitor: BackpressureMonitor

    @property
    def kept_paths(self) -> list[str]:
        return sorted(h.path for h in self.kept)


async def scan(
    site: Site,
    entries: list[str],
    *,
    rps: int = 50,
    maxtime: int = 60,
    host_header: str | None = None,
) -> Outcome:
    cal = calibration_strings()
    baselines = get_baselines(site, cal)
    since = len(site.log)
    monitor = BackpressureMonitor()
    with tempfile.TemporaryDirectory(prefix="sentinel-test-") as tmp:
        wl = Path(tmp) / "paths.txt"
        wl.write_text("\n".join(entries) + "\n")
        args = build_args(site.base, str(wl), cal, rps, maxtime, host_header=host_header)
        run = await run_ffuf(
            args,
            timeout_s=maxtime + 30,
            on_hit=lambda h: monitor.observe(h.status),
            stop_hint=lambda: monitor.reason,
            workdir=tmp,
        )
    kept, dropped, catch_all = filter_hits(run.hits, baselines, len(entries))
    return Outcome(run, kept, dropped, catch_all, since, cal, entries, monitor)


def assert_only_wordlist_and_calibration_requested(site: Site, out: Outcome) -> set[str]:
    allowed = {"/" + e for e in out.entries} | {"/" + c for c in out.cal}
    seen = set(site.paths(out.since))
    assert seen <= allowed, f"unexpected requests: {sorted(seen - allowed)}"
    for path in seen:
        # ffuf's built-in calibration (admin<random>, .htaccess<random>) never runs
        assert not path.startswith("/.htaccess")
        assert not (path.startswith("/admin") and path != "/admin")
    return seen


def max_requests_per_second(site: Site, since: int, *, skip: frozenset[str] = frozenset()) -> float:
    """Most requests the server saw in any one-second window (paths in `skip` ignored)."""
    times = [t for t, _, path, _ in site.log[since:] if path not in skip]
    best = 0
    for i, start in enumerate(times):
        best = max(best, sum(1 for t in times[i:] if t < start + 1.0))
    return float(best)


# --- the normal site ---


async def test_normal_site_yields_exactly_its_real_paths(serve):
    site = serve(normal_site)
    out = await scan(site, wordlist(), rps=50)
    assert out.kept_paths == sorted(REAL)
    by_path = {h.path: h for h in out.kept}
    assert by_path[".env"].status == 200
    assert by_path["admin"].status == 301 and by_path["admin"].redirect == "/admin/"
    assert by_path["config.json"].status == 403
    assert out.catch_all is False
    assert out.run.stop_reason is None
    assert out.run.result.ran and out.run.result.returncode == 0

    seen = assert_only_wordlist_and_calibration_requested(site, out)
    assert {"/" + c for c in out.cal} <= seen  # our calibration strings were used
    assert {"/" + e for e in out.entries} <= seen  # and the whole wordlist was walked


async def test_nothing_but_get_requests_with_our_user_agent(serve):
    site = serve(normal_site)
    out = await scan(site, wordlist(fillers=20), rps=100)
    for _, method, _, headers in site.log[out.since :]:
        assert method == "GET"
        assert headers["User-Agent"] == USER_AGENT


async def test_host_header_is_sent_when_pinned(serve):
    site = serve(normal_site)
    out = await scan(site, wordlist(fillers=10), rps=100, host_header="shop.example.test")
    assert out.kept_paths == sorted(REAL)
    hosts = {h.get("Host") for _, _, _, h in site.log[out.since :]}
    assert hosts == {"shop.example.test"}


async def test_observed_request_rate_stays_within_the_rate_limit(serve):
    """-rate is honoured for the wordlist. ffuf sends its calibration requests (one
    per -acc string) at once at the start, outside the rate limiter, so the very
    first second can carry that many extra."""
    site = serve(normal_site)
    rps = 20
    out = await scan(site, wordlist(fillers=60), rps=rps)
    assert out.kept_paths == sorted(REAL)
    count = len(site.log) - out.since
    assert count >= 60 + len(out.cal)

    cal_paths = frozenset("/" + c for c in out.cal)
    # (+1: requests 50 ms apart can put 21 inside a closed one-second window by jitter)
    assert max_requests_per_second(site, out.since, skip=cal_paths) <= rps + 1
    assert max_requests_per_second(site, out.since) <= rps + 1 + len(out.cal)
    # and after the calibration burst the average stays at the limit too
    later = site.log[out.since + len(out.cal) :]
    assert len(later) / max(later[-1][0] - later[0][0], 0.001) <= rps * 1.1


# --- hosts that answer everything ---


async def test_catch_all_200_site_yields_nothing(serve):
    site = serve(catch_all_site)
    out = await scan(site, wordlist(), rps=100)
    assert out.kept == []
    assert out.run.hits == []  # ffuf's calibration with our -acc strings already hid them all
    assert out.catch_all is False
    assert_only_wordlist_and_calibration_requested(site, out)


async def test_redirect_everything_to_login_yields_nothing(serve):
    site = serve(redirect_all_site)
    out = await scan(site, wordlist(), rps=100)
    assert out.kept == []
    assert out.run.hits == []
    assert_only_wordlist_and_calibration_requested(site, out)


async def test_filter_hits_alone_handles_what_calibration_missed(serve):
    """Even if ffuf's own calibration let everything through, the baselines
    taken by the caller drop it."""
    for respond in (catch_all_site, redirect_all_site):
        site = serve(respond)
        cal = calibration_strings()
        baselines = get_baselines(site, cal)
        # a run without ffuf's -ac: build the args and strip calibration out
        entries = wordlist(fillers=40)
        with tempfile.TemporaryDirectory(prefix="sentinel-test-") as tmp:
            wl = Path(tmp) / "paths.txt"
            wl.write_text("\n".join(entries) + "\n")
            args = build_args(site.base, str(wl), cal, 100, 60)
            cut = args.index("-ac")
            end = args.index("-mc")
            raw = await run_ffuf(args[:cut] + args[end:], timeout_s=60, workdir=tmp)
        assert len(raw.hits) >= len(entries) - 1  # ffuf alone reports (nearly) everything
        kept, dropped, _ = filter_hits(raw.hits, baselines, len(entries))
        assert kept == [], dropped


# --- backpressure ---


async def test_429_site_is_reported_through_the_stop_reason(serve):
    site = serve(always_429)
    out = await scan(site, wordlist(fillers=150), rps=50)
    assert out.kept == []
    assert out.run.stop_reason == "rate limited (429)"
    requested = len(site.log) - out.since
    assert requested < len(out.entries)  # it stopped before the end of the wordlist
    assert_only_wordlist_and_calibration_requested(site, out)


async def test_a_host_that_starts_throttling_part_way_is_stopped(serve):
    def throttles(path: str, n: int) -> Response:
        if n > 40:
            return 429, {}, b"slow down"
        return normal_site(path, n)

    site = serve(throttles)
    out = await scan(site, wordlist(fillers=250), rps=60)
    # either our monitor (5 hits in a row) or ffuf's own -sa gets there first
    assert out.run.stop_reason is not None
    assert "pushed back" in out.run.stop_reason or out.run.stop_reason == "rate limited (429)"
    assert len(site.log) - out.since < len(out.entries) + len(out.cal)
    assert out.kept == [] or {h.path for h in out.kept} <= set(REAL)


async def test_503_hits_trip_the_backpressure_monitor(serve):
    """ffuf's calibration hides a uniform 503, so use a host that sends 503 only for
    some paths: the callback sees those hits and stops the run."""

    def flaky(path: str, n: int) -> Response:
        if path.startswith("/page") and int(path[5:] or 0) % 2 == 0 and int(path[5:] or 0) > 10:
            return 503, {}, b"busy"
        return normal_site(path, n)

    site = serve(flaky)
    out = await scan(site, wordlist(fillers=200), rps=100)
    assert out.monitor.stopped
    assert out.run.stop_reason and "pushed back" in out.run.stop_reason
    assert out.run.result.stopped_reason is not None
    assert len(site.log) - out.since < len(out.entries)


# --- no stray processes, no leftover state ---


async def test_ffuf_leaves_nothing_behind_in_the_real_home(serve, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    site = serve(normal_site)
    out = await scan(site, wordlist(fillers=5), rps=100)
    assert out.kept_paths == sorted(REAL)
    assert list(fake_home.rglob("*")) == []
