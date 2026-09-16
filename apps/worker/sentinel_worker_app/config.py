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


def get_settings() -> Settings:
    return Settings()
