"""The "custom multi-tenant fixture" referenced throughout the roadmap
(docs/05-v1-roadmap.md M0's benchmark corpus, M2's exit criterion: "find
every planted IDOR/authz bug and flag zero known-good endpoints").

Three users, two tenants:
- alice (tenant "acme", member) owns a private note with a unique canary.
- bob (tenant "beta", member) owns a different private note, different tenant.
- carol (tenant "acme", admin) can reach an admin dashboard alice/bob cannot.

One planted bug: GET /notes/{note_id} has no ownership check at all — any
logged-in user can read any note by ID (a real horizontal/cross-tenant
IDOR). One deliberately *safe* endpoint alongside it: GET /admin/dashboard
is properly role-gated, so the same replay-and-judge machinery that catches
the bug must also correctly find nothing wrong here — the false-positive
side of the product's core claim, exercised as a fixture, not just an
assertion.
"""

from __future__ import annotations

import secrets
from typing import TypedDict

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route


class _User(TypedDict):
    password: str
    tenant: str
    role: str
    note_id: str | None


USERS: dict[str, _User] = {
    "alice": {
        "password": "alice-pw-093",
        "tenant": "acme",
        "role": "member",
        "note_id": "note-alice",
    },
    "bob": {"password": "bob-pw-471", "tenant": "beta", "role": "member", "note_id": "note-bob"},
    "carol": {"password": "carol-pw-582", "tenant": "acme", "role": "admin", "note_id": None},
}
NOTES = {
    "note-alice": "canary-alice-9f3d1",
    "note-bob": "canary-bob-7a2c4",
}

_SESSIONS: dict[str, str] = {}  # token -> username

LOGIN_FORM = """
<html><body>
<h1>Sign in</h1>
<form method="post" action="/login">
  <input name="username" type="text" />
  <input name="password" type="password" />
  <button type="submit">Log in</button>
</form>
</body></html>
"""

DASHBOARD_HTML = """<html><body><h1>Dashboard</h1><a href="/">Home</a></body></html>"""

HOME_ANON_HTML = """<html><body><h1>Welcome</h1><a href="/login">Log in</a></body></html>"""

HOME_MEMBER_HTML = """
<html><body>
<h1>Welcome, {username}!</h1>
<a href="/notes/{note_id}">My note</a>
</body></html>
"""

HOME_ADMIN_HTML = """
<html><body>
<h1>Welcome, {username}!</h1>
<a href="/admin/dashboard">Admin dashboard</a>
</body></html>
"""


def _session_user(request: Request) -> tuple[str, _User] | None:
    token = request.cookies.get("session")
    username = _SESSIONS.get(token) if token else None
    if username is None:
        return None
    return username, USERS[username]


async def home(request: Request) -> HTMLResponse:
    session_user = _session_user(request)
    if session_user is None:
        return HTMLResponse(HOME_ANON_HTML)
    username, user = session_user
    if user["role"] == "admin":
        return HTMLResponse(HOME_ADMIN_HTML.format(username=username))
    return HTMLResponse(HOME_MEMBER_HTML.format(username=username, note_id=user["note_id"]))


async def login_form(request: Request) -> HTMLResponse:
    return HTMLResponse(LOGIN_FORM)


async def login_submit(request: Request) -> RedirectResponse:
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    user = USERS.get(username) if isinstance(username, str) else None
    if user is not None and isinstance(username, str) and user["password"] == password:
        token = secrets.token_hex(16)
        _SESSIONS[token] = username
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie("session", token, httponly=True)
        return response
    return RedirectResponse(url="/login?error=1", status_code=303)


async def dashboard(request: Request) -> HTMLResponse | RedirectResponse:
    if _session_user(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    return HTMLResponse(DASHBOARD_HTML)


async def notes(request: Request) -> JSONResponse:
    # The planted bug: any authenticated user, regardless of tenant or
    # role, can read any note by ID. No ownership check whatsoever.
    if _session_user(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    note_id = request.path_params["note_id"]
    content = NOTES.get(note_id)
    if content is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"note": content})


async def admin_dashboard(request: Request) -> JSONResponse:
    session_user = _session_user(request)
    if session_user is None or session_user[1]["role"] != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse({"page": "admin dashboard", "widgets": ["users", "billing"]})


app = Starlette(
    routes=[
        Route("/", home),
        Route("/login", login_form, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/dashboard", dashboard),
        Route("/notes/{note_id}", notes),
        Route("/admin/dashboard", admin_dashboard),
    ]
)
