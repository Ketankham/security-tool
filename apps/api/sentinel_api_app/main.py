"""FastAPI control plane entrypoint (docs/01-architecture.md §4)."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .routers import findings, health, organizations, personas, scans, targets


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel API",
        description="Control plane: orgs, targets, personas, scans, findings.",
        version="0.1.0",
    )

    app.include_router(health.router)
    app.include_router(organizations.router)
    app.include_router(targets.router)
    app.include_router(personas.router)
    app.include_router(scans.router)
    app.include_router(findings.router)

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(request: Request, exc: RuntimeError) -> JSONResponse:
        # e.g. KMS_MASTER_KEY missing — a config problem, not a client error,
        # but callers still deserve a structured response rather than a 500 stack trace.
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    return app


app = create_app()
