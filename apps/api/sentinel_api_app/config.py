from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    api_secret_key: str = "change-me-in-real-envs"

    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    redis_url: str = "redis://localhost:6379/0"

    kms_master_key: str = ""  # required outside dev; see sentinel_core.crypto

    # Must match the worker's equivalent settings — both read/write the same
    # physical location (docs/01 §3.1: content-addressed, shared storage).
    storage_backend: str = "local"
    storage_local_path: str = "./data/transcripts"
    report_local_path: str = "./data/reports"

    # POST /quick-scan bypasses ownership verification and persona setup for
    # a bare URL (docs/06-safety-legal-abuse.md §1 is a legal gate, not a
    # formality) — off by default, and never intended for a customer-facing
    # deployment. See routers/quick_scan.py's module docstring.
    enable_quick_scan: bool = False

    # Clerk (control-plane auth). Unset in dev — see app.deps.get_current_org
    # for the stub that stands in until this is wired.
    clerk_secret_key: str = ""
    clerk_publishable_key: str = ""


def get_settings() -> Settings:
    return Settings()
