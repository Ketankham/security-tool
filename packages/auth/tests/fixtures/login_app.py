"""A tiny, real HTTP app with a form login, used to test LoginReplayer and
SessionOracle end to end — a real bound server so Playwright can actually
drive a browser against it, not a mock.
"""

from __future__ import annotations

import secrets

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

VALID_USERNAME = "alice"
VALID_PASSWORD = "correct-horse-battery-staple"

# In-memory "sessions" — token -> username. Good enough for a test fixture;
# nothing about this belongs anywhere near production code.
_SESSIONS: dict[str, str] = {}

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

DASHBOARD_HTML = """
<html><body>
<h1>Dashboard</h1>
<p>Welcome back, {username}!</p>
</body></html>
"""


async def login_form(request: Request) -> HTMLResponse:
    return HTMLResponse(LOGIN_FORM)


async def login_submit(request: Request) -> RedirectResponse:
    form = await request.form()
    username = form.get("username")
    password = form.get("password")

    if username == VALID_USERNAME and password == VALID_PASSWORD:
        token = secrets.token_hex(16)
        _SESSIONS[token] = username
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie("session", token, httponly=True)
        return response

    return RedirectResponse(url="/login?error=1", status_code=303)


def _session_username(request: Request) -> str | None:
    token = request.cookies.get("session")
    if token is None:
        return None
    return _SESSIONS.get(token)


async def dashboard(request: Request) -> HTMLResponse | RedirectResponse:
    username = _session_username(request)
    if username is None:
        return RedirectResponse(url="/login", status_code=303)
    return HTMLResponse(DASHBOARD_HTML.format(username=username))


async def api_me(request: Request) -> JSONResponse:
    username = _session_username(request)
    if username is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"username": username})


async def logout(request: Request) -> RedirectResponse:
    token = request.cookies.get("session")
    if token is not None:
        _SESSIONS.pop(token, None)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session")
    return response


app = Starlette(
    routes=[
        Route("/login", login_form, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/dashboard", dashboard, methods=["GET"]),
        Route("/api/me", api_me, methods=["GET"]),
        Route("/logout", logout, methods=["POST"]),
    ]
)
