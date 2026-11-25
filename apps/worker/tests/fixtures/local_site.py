"""A throwaway HTTP site on 127.0.0.1 that records every request it receives.

The directory brute force tests point the real ffuf and the real HttpEngine at
one of these and then read ``site.requests`` to check exactly what was (and was
not) sent. Runs in a thread so it keeps answering while ffuf, a separate
process, and the event loop under test are busy.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass(frozen=True, slots=True)
class Reply:
    status: int = 200
    body: bytes | str = b""
    ctype: str | None = "text/html"
    headers: dict[str, str] = field(default_factory=dict)
    # HEAD answers advertise this length instead of len(body) (a big file).
    advertised_length: int | None = None


@dataclass(frozen=True, slots=True)
class Seen:
    method: str
    path: str
    host: str
    at: float
    number: int


Decider = Callable[[str, str, str, int], Reply | None]


class LocalSite:
    """``routes`` maps a path (with its leading "/") to a Reply. Anything else
    goes to ``decide(method, path, host, number)`` (a Reply, or None for 404)."""

    def __init__(
        self,
        routes: dict[str, Reply] | None = None,
        decide: Decider | None = None,
        port: int = 0,
    ) -> None:
        self.routes = dict(routes or {})
        self.decide = decide
        self.requests: list[Seen] = []
        self._lock = threading.Lock()
        site = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                path = self.path.split("?", 1)[0]
                host = self.headers.get("Host", "")
                with site._lock:
                    number = len(site.requests) + 1
                    site.requests.append(
                        Seen(self.command, self.path, host, time.monotonic(), number)
                    )
                reply = site.routes.get(path)
                if reply is None and site.decide is not None:
                    reply = site.decide(self.command, path, host, number)
                if reply is None:
                    reply = Reply(404, "not found")
                body = reply.body.encode() if isinstance(reply.body, str) else reply.body
                self.send_response(reply.status)
                if reply.ctype:
                    self.send_header("Content-Type", reply.ctype)
                length = (
                    reply.advertised_length
                    if self.command == "HEAD" and reply.advertised_length is not None
                    else len(body)
                )
                self.send_header("Content-Length", str(length))
                for key, value in reply.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = _serve
            do_HEAD = _serve
            do_POST = _serve
            do_PUT = _serve
            do_DELETE = _serve

            def log_message(self, *args) -> None:  # silence the default stderr log
                return None

        self._server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self._server.daemon_threads = True
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> LocalSite:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def paths(self) -> list[str]:
        return [r.path for r in self.requests]

    def count(self, path: str) -> int:
        return sum(1 for r in self.requests if r.path == path)


def catch_all_page(body: str = "<html><body>Welcome to the site</body></html>") -> Decider:
    """200 with the same page for every path."""

    def decide(_method: str, _path: str, _host: str, _n: int) -> Reply:
        return Reply(200, body)

    return decide


def redirect_everything(to: str = "/login") -> Decider:
    """302 to /login for every path (and /login itself answers 200)."""

    def decide(_method: str, path: str, _host: str, _n: int) -> Reply:
        if path == to:
            return Reply(200, "<html><body>Please sign in</body></html>")
        return Reply(302, b"", headers={"Location": f"{to}?next={path}"})

    return decide


def rate_limit_after(n_ok: int) -> Decider:
    """The first ``n_ok`` requests get the normal 404; every later one is 429."""

    def decide(_method: str, _path: str, _host: str, n: int) -> Reply | None:
        return Reply(429, "slow down", headers={"Retry-After": "1"}) if n > n_ok else None

    return decide


ENV_SECRET = "hunter2secret-DB-PASSWORD-value"
ENV_BODY = (
    "APP_ENV=production\nDB_HOST=db.internal\n"
    f"DB_PASSWORD={ENV_SECRET}\nAPI_KEY=sk-live-0123456789abcdef\n"
)


def planted_site() -> dict[str, Reply]:
    """A small site with the things the brute force should find."""
    return {
        "/": Reply(200, "<html><body><h1>Shop</h1></body></html>"),
        "/.env": Reply(200, ENV_BODY, ctype="text/plain"),
        "/.git/HEAD": Reply(200, "ref: refs/heads/main\n", ctype="text/plain"),
        "/admin/": Reply(200, "<html><body>admin area</body></html>"),
        "/backup.zip": Reply(
            200, b"PK\x03\x04" + b"\0" * 64, ctype="application/zip", advertised_length=4096
        ),
        "/robots.txt": Reply(200, "User-agent: *\nDisallow: /secret-area/\n", ctype="text/plain"),
        "/secret-area/x": Reply(200, "secret"),
    }
