from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    redis_url: str = "redis://localhost:6379/0"
    storage_backend: str = "local"
    storage_local_path: str = "./data/transcripts"
    report_local_path: str = "./data/reports"
    kms_master_key: str = ""  # required for AUTH_ESTABLISHING — see sentinel_core.crypto

    # The ownership-verification gate (docs/06-safety-legal-abuse.md §1):
    # a target must prove domain ownership (DNS TXT / well-known file / meta
    # tag) and accept authorization before any scan. On by default. A
    # deployment that only tests client portals it is engaged on may turn it
    # off (REQUIRE_OWNERSHIP_VERIFICATION=false); the ScopeGuard still
    # confines every request to the target's own hosts + scope rules.
    # Must match the API's setting.
    require_ownership_verification: bool = True

    # A scan still running after this long is stopped and marked FAILED
    # instead of holding the (single) scan worker forever.
    scan_time_limit_s: int = 3 * 3600

    # On start-up, mark scans left mid-run by a previous worker process as
    # FAILED (scan_runner.fail_interrupted_scans). Only correct while one
    # scan worker runs; the login-test worker turns it off.
    sweep_interrupted_scans: bool = True


def get_settings() -> Settings:
    return Settings()
