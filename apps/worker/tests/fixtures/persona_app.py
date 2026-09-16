"""A tiny app whose home page's content genuinely differs by auth state —
the exact mechanic sentinel_auth's session oracle and sentinel_crawler's
per-persona surface diff both depend on. Unauthenticated visitors see a
login link; authenticated visitors see /dashboard and /settings links that
don't exist anywhere in the anonymous page's HTML.
"""

from __future__ import annotations

import secrets

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

VALID_USERNAME = "alice"
VALID_PASSWORD = "correct-horse-battery-staple"

_SESSIONS: dict[str, str] = {}

HOME_ANON_HTML = """
<html><body><h1>Welcome</h1><a href="/login">Log in</a></body></html>
"""

HOME_AUTH_HTML = """
<html><body>
<h1>Welcome back, {username}!</h1>
<a href="/dashboard">Dashboard</a>
<a href="/settings">Settings</a>
</body></html>
"""

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
SETTINGS_HTML = """<html><body><h1>Settings</h1><a href="/">Home</a></body></html>"""


def _session_username(request: Request) -> str | None:
    token = request.cookies.get("session")
    return _SESSIONS.get(token) if token else None


async def home(request: Request) -> HTMLResponse:
    username = _session_username(request)
    if username is None:
        return HTMLResponse(HOME_ANON_HTML)
    return HTMLResponse(HOME_AUTH_HTML.format(username=username))


async def login_form(request: Request) -> HTMLResponse:
    return HTMLResponse(LOGIN_FORM)


async def login_submit(request: Request) -> RedirectResponse:
    form = await request.form()
    if form.get("username") == VALID_USERNAME and form.get("password") == VALID_PASSWORD:
        token = secrets.token_hex(16)
        _SESSIONS[token] = VALID_USERNAME
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie("session", token, httponly=True)
        return response
    return RedirectResponse(url="/login?error=1", status_code=303)


async def dashboard(request: Request) -> HTMLResponse | RedirectResponse:
    if _session_username(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    return HTMLResponse(DASHBOARD_HTML)


async def settings_page(request: Request) -> HTMLResponse | RedirectResponse:
    if _session_username(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    return HTMLResponse(SETTINGS_HTML)


async def api_me(request: Request) -> JSONResponse:
    username = _session_username(request)
    if username is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"username": username})


app = Starlette(
    routes=[
        Route("/", home),
        Route("/login", login_form, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/dashboard", dashboard),
        Route("/settings", settings_page),
        Route("/api/me", api_me),
    ]
)
