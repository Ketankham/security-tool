from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class DbSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    database_url_sync: str = "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel"
