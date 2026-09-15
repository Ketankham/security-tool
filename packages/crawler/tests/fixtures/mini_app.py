"""A tiny multi-page site for testing PersonaCrawler end to end: same-origin
links, an off-origin link (must be skipped), a destructive-looking link
(must be recorded but never followed), a form (recorded, never submitted),
numeric-ID pages (to prove path-template collapsing), and a JS-only fetch
call to an endpoint with no visible link at all (proves the network-
interception "JS extraction" half of Phase 3 actually finds something a
static crawler would miss).
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

HOME_HTML = """
<html><body>
<h1>Home</h1>
<a href="/profile">Profile</a>
<a href="/about">About</a>
<a href="/users/42">User 42</a>
<a href="/users/7">User 7</a>
<a href="/account/delete">Delete my account</a>
<a href="https://example.com/">External</a>
<script>fetch('/api/hidden-admin-data');</script>
</body></html>
"""

PROFILE_HTML = """
<html><body>
<h1>Profile</h1>
<a href="/">Home</a>
<form action="/contact" method="post">
  <input name="message" />
  <button type="submit">Send</button>
</form>
</body></html>
"""

ABOUT_HTML = """<html><body><h1>About</h1><a href="/">Home</a></body></html>"""
USER_HTML = """<html><body><h1>User page</h1><a href="/">Home</a></body></html>"""


async def home(request: Request) -> HTMLResponse:
    return HTMLResponse(HOME_HTML)


async def profile(request: Request) -> HTMLResponse:
    return HTMLResponse(PROFILE_HTML)


async def about(request: Request) -> HTMLResponse:
    return HTMLResponse(ABOUT_HTML)


async def user_page(request: Request) -> HTMLResponse:
    return HTMLResponse(USER_HTML)


async def hidden_admin_data(request: Request) -> JSONResponse:
    return JSONResponse({"secret": "only findable via JS extraction"})


async def account_delete(request: Request) -> HTMLResponse:
    # If the crawler ever actually navigates here, that's a real bug — the
    # test asserts this page is never visited.
    return HTMLResponse("<html><body>Account deleted!</body></html>")


app = Starlette(
    routes=[
        Route("/", home),
        Route("/profile", profile),
        Route("/about", about),
        Route("/users/{user_id}", user_page),
        Route("/api/hidden-admin-data", hidden_admin_data),
        Route("/account/delete", account_delete),
    ]
)
