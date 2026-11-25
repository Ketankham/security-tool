"""FastAPI control plane entrypoint (docs/01-architecture.md §4)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import Settings, get_settings
from .identity import USERNAME_RE, resolve_identity
from .routers import (
    findings,
    health,
    me,
    organizations,
    personas,
    quick_scan,
    reports,
    scan_insight,
    scans,
    targets,
)

# Reachable without an identity so the proxy and container health checks work.
_IDENTITY_EXEMPT_PATHS = ("/healthz",)

NOT_SIGNED_IN = (
    "Not signed in. Open Sentinel through its sign-in page (/security); "
    "requests that bypass the sign-in proxy are refused."
)


def check_identity_settings(settings: Settings) -> None:
    """Refuse to start in a configuration that would make identity meaningless."""
    if settings.require_identity and not settings.proxy_shared_secret:
        raise RuntimeError(
            "REQUIRE_IDENTITY is on but SENTINEL_PROXY_SECRET is empty: the API would "
            "have no way to tell the sign-in proxy from anyone else. Set the secret."
        )
    if settings.dev_identity and settings.environment == "production":
        raise RuntimeError(
            "DEV_IDENTITY is set while ENVIRONMENT=production. It makes every request "
            "pose as that user; it is for local development only. Unset it."
        )
    if settings.dev_identity and not USERNAME_RE.fullmatch(settings.dev_identity):
        raise RuntimeError(
            "DEV_IDENTITY is not a valid username (lower-case letters, digits, '.', '_', '-'; "
            "at most 32 characters)."
        )


def create_app() -> FastAPI:
    check_identity_settings(get_settings())
    app = FastAPI(
        title="Sentinel API",
        description="Control plane: orgs, targets, personas, scans, findings.",
        version="0.1.0",
    )

    @app.middleware("http")
    async def identity_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Settings are read per request (like the other settings-driven checks)
        # so a deployment's environment is what decides, not import order.
        settings = get_settings()
        identity = resolve_identity(request, settings)
        request.state.identity = identity
        request.state.identity_resolved = True
        if (
            settings.require_identity
            and identity is None
            and request.url.path not in _IDENTITY_EXEMPT_PATHS
        ):
            return JSONResponse(status_code=401, content={"detail": NOT_SIGNED_IN})
        return await call_next(request)

    # The dashboard (apps/web) is a separate origin, so the browser needs
    # CORS to call this API directly. Origins are config-driven; the dev
    # auth stand-in header (X-Org-Id) must be allowed through.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_allow_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(organizations.router)
    app.include_router(targets.router)
    app.include_router(personas.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(scan_insight.router)
    app.include_router(quick_scan.router)

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(request: Request, exc: RuntimeError) -> JSONResponse:
        # e.g. KMS_MASTER_KEY missing — a config problem, not a client error,
        # but callers still deserve a structured response rather than a 500 stack trace.
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    return app


app = create_app()
