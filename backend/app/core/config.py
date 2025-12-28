from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    database_url: str = Field(
        default="postgresql+psycopg2://mailtriage:mailtriage@postgres:5432/mailtriage",
        alias="DATABASE_URL",
    )
    admin_username: Optional[str] = Field(default=None, alias="ADMIN_USERNAME")
    admin_password: Optional[str] = Field(default=None, alias="ADMIN_PASSWORD")
    reporter_hash_salt: str = Field(default="change-me", alias="REPORTER_HASH_SALT")
    cors_origins: List[str] = Field(default=["http://localhost:3000"], alias="CORS_ORIGINS")

    minio_endpoint: str = Field(default="http://minio:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="minioadmin", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="minioadmin", alias="MINIO_SECRET_KEY")
    minio_bucket: str = Field(default="mailtriage", alias="MINIO_BUCKET")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
