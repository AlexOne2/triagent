from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    database_url: str = Field(
        default="postgresql+psycopg2://triagent:triagent@postgres:5432/triagent",
        alias="DATABASE_URL",
    )

    # Legacy bootstrap credentials and optional temporary basic-auth bridge
    admin_username: Optional[str] = Field(default="admin", alias="ADMIN_USERNAME")
    admin_password: Optional[str] = Field(default="change-me", alias="ADMIN_PASSWORD")

    reporter_hash_salt: str = Field(default="change-me", alias="REPORTER_HASH_SALT")
    cors_origins: str = Field(default="http://localhost:3000", alias="CORS_ORIGINS")

    auth_mode: str = Field(default="session_rbac", alias="AUTH_MODE")
    auth_session_ttl_minutes: int = Field(default=480, alias="AUTH_SESSION_TTL_MINUTES")
    auth_legacy_basic_enabled: bool = Field(default=True, alias="AUTH_LEGACY_BASIC_ENABLED")
    auth_password_min_length: int = Field(default=14, alias="AUTH_PASSWORD_MIN_LENGTH")
    auth_lockout_threshold: int = Field(default=5, alias="AUTH_LOCKOUT_THRESHOLD")
    auth_lockout_window_minutes: int = Field(default=15, alias="AUTH_LOCKOUT_WINDOW_MINUTES")
    auth_lockout_duration_minutes: int = Field(default=15, alias="AUTH_LOCKOUT_DURATION_MINUTES")
    auth_dns_enabled: bool = Field(default=True, alias="AUTH_DNS_ENABLED")
    auth_dns_timeout_seconds: float = Field(default=2.0, alias="AUTH_DNS_TIMEOUT_SECONDS")

    audit_retention_days: int = Field(default=395, alias="AUDIT_RETENTION_DAYS")
    audit_export_enabled: bool = Field(default=True, alias="AUDIT_EXPORT_ENABLED")
    audit_export_storage: str = Field(default="filesystem", alias="AUDIT_EXPORT_STORAGE")
    audit_export_bucket: str = Field(default="triagent-audit", alias="AUDIT_EXPORT_BUCKET")
    audit_export_path: str = Field(default="/tmp/triagent-audit", alias="AUDIT_EXPORT_PATH")
    audit_max_metadata_bytes: int = Field(default=8192, alias="AUDIT_MAX_METADATA_BYTES")

    minio_endpoint: str = Field(default="http://minio:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="minioadmin", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="minioadmin", alias="MINIO_SECRET_KEY")
    minio_bucket: str = Field(default="triagent", alias="MINIO_BUCKET")

    def cors_origins_list(self) -> List[str]:
        if not self.cors_origins:
            return []
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
