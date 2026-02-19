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
    cors_origins: str = Field(default="http://localhost:3000", alias="CORS_ORIGINS")

    minio_endpoint: str = Field(default="http://minio:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="minioadmin", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="minioadmin", alias="MINIO_SECRET_KEY")
    minio_bucket: str = Field(default="mailtriage", alias="MINIO_BUCKET")

    def cors_origins_list(self) -> List[str]:
        if not self.cors_origins:
            return []
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
