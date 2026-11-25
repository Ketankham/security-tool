from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    api_secret_key: str = "change-me-in-real-envs"

    # Browser origins allowed to call this API (the Next.js dashboard in
    # apps/web). Comma-separated; dev default is the local Next server.
    # In production set this to the dashboard's real origin(s).
    cors_allow_origins: str = "http://localhost:3000"

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

    # The ownership-verification gate (docs/06-safety-legal-abuse.md §1):
    # a target must prove domain ownership (DNS TXT / well-known file / meta
    # tag) and accept authorization before any scan. On by default. A
    # deployment that only tests client portals it is engaged on may turn it
    # off (REQUIRE_OWNERSHIP_VERIFICATION=false); the ScopeGuard still
    # confines every request to the target's own hosts + scope rules.
    # Must match the worker's setting.
    require_ownership_verification: bool = True

    # Who is calling (see identity.py). In production every request reaches the
    # API through the Caddy sign-in proxy, which sets X-Sentinel-User to the
    # signed-in username and X-Sentinel-Proxy-Secret to a shared secret; the
    # API trusts the user header only when that secret matches.
    #   REQUIRE_IDENTITY=true     refuse (401) any request without a verified identity
    #                             except /healthz; needs SENTINEL_PROXY_SECRET
    #   SENTINEL_PROXY_SECRET     the shared secret the proxy sends
    #   DEV_IDENTITY=<username>   local development only: pretend every request is
    #                             this user. Refused at startup when ENVIRONMENT=production.
    require_identity: bool = False
    proxy_shared_secret: str = Field(
        default="",
        validation_alias=AliasChoices("SENTINEL_PROXY_SECRET", "proxy_shared_secret"),
    )
    dev_identity: str = ""

    # Clerk (control-plane auth). Unset in dev — see app.deps.get_current_org
    # for the stub that stands in until this is wired.
    clerk_secret_key: str = ""
    clerk_publishable_key: str = ""

    @property
    def cors_allow_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]


def get_settings() -> Settings:
    return Settings()
