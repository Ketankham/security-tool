"""A tiny, real multi-tenant / multi-role app for exercising the
authorization engine end to end (docs/03 §4). It has, side by side:

- SECURE endpoints that correctly enforce ownership and role (must produce
  ZERO findings), and
- LEAKY endpoints with planted broken-access-control bugs (must be caught,
  and — because each private profile carries a unique canary — CONFIRMED).

A real bound server so the engine drives it through the actual HttpEngine,
cookies and all, not a mock.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# token -> (persona_id, tenant, role)
SESSIONS = {
    "tok-admin-a": ("admin-a", "A", "admin"),
    "tok-member-a": ("member-a", "A", "member"),
    "tok-admin-b": ("admin-b", "B", "admin"),
    "tok-member-b": ("member-b", "B", "member"),
}

# Each persona's private profile carries a unique canary — the deterministic
# proof that a leak exposed *that persona's* data (docs/03 §4.4 Layer 3).
CANARY = {
    "admin-a": "CANARY-ADMIN-A-7f3e9c",
    "member-a": "CANARY-MEMBER-A-1a2b3c",
    "admin-b": "CANARY-ADMIN-B-9d8e7f",
    "member-b": "CANARY-MEMBER-B-4c5d6e",
}


def _profile_body(persona_id: str) -> dict:
    return {
        "persona": persona_id,
        "email": f"{persona_id}@example.invalid",
        "private_note": f"Secret for {persona_id}: {CANARY[persona_id]}",
        "padding": "x" * 200,  # make bodies substantial and similar-sized
    }


def _identify(request: Request):
    token = request.cookies.get("session")
    return SESSIONS.get(token or "")


# --- SECURE: only the owner may read their profile (must yield NO findings) ---
async def secure_profile(request: Request) -> JSONResponse:
    me = _identify(request)
    target = request.path_params["persona"]
    if me is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if me[0] != target:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse(_profile_body(target))


# --- LEAKY: returns any profile to any caller (planted BOLA/IDOR) ---
async def leaky_profile(request: Request) -> JSONResponse:
    me = _identify(request)
    target = request.path_params["persona"]
    if me is None:
        # Still leaks to anonymous — the anonymous-boundary bug.
        return JSONResponse(_profile_body(target))
    return JSONResponse(_profile_body(target))


# --- PUBLIC: identical for everyone (must yield NO findings) ---
async def public_health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "version": "1.2.3", "padding": "z" * 200})


app = Starlette(
    routes=[
        Route("/api/profile/{persona}", secure_profile, methods=["GET"]),
        Route("/api/leaky/profile/{persona}", leaky_profile, methods=["GET"]),
        Route("/api/health", public_health, methods=["GET"]),
    ]
)
