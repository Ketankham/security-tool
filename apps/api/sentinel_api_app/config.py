from __future__ import annotations

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

    # Clerk (control-plane auth). Unset in dev — see app.deps.get_current_org
    # for the stub that stands in until this is wired.
    clerk_secret_key: str = ""
    clerk_publishable_key: str = ""

    @property
    def cors_allow_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]


def get_settings() -> Settings:
    return Settings()
