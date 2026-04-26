import json
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
    auth_demo_enabled: bool = Field(default=True, alias="AUTH_DEMO_ENABLED")
    auth_demo_session_ttl_minutes: int = Field(default=120, alias="AUTH_DEMO_SESSION_TTL_MINUTES")
    auth_demo_retention_hours: int = Field(default=24, alias="AUTH_DEMO_RETENTION_HOURS")
    auth_demo_split: str = Field(default="demo", alias="AUTH_DEMO_SPLIT")
    auth_ldap_enabled: bool = Field(default=False, alias="AUTH_LDAP_ENABLED")
    auth_ldap_server_uri: Optional[str] = Field(default=None, alias="AUTH_LDAP_SERVER_URI")
    auth_ldap_bind_dn: Optional[str] = Field(default=None, alias="AUTH_LDAP_BIND_DN")
    auth_ldap_bind_password: Optional[str] = Field(default=None, alias="AUTH_LDAP_BIND_PASSWORD")
    auth_ldap_base_dn: Optional[str] = Field(default=None, alias="AUTH_LDAP_BASE_DN")
    auth_ldap_user_filter: str = Field(
        default="(&(objectClass=person)(|(uid={username})(sAMAccountName={username})(userPrincipalName={username})))",
        alias="AUTH_LDAP_USER_FILTER",
    )
    auth_ldap_group_attribute: str = Field(default="memberOf", alias="AUTH_LDAP_GROUP_ATTRIBUTE")
    auth_ldap_email_attribute: str = Field(default="mail", alias="AUTH_LDAP_EMAIL_ATTRIBUTE")
    auth_ldap_start_tls: bool = Field(default=False, alias="AUTH_LDAP_START_TLS")
    auth_ldap_verify_certs: bool = Field(default=True, alias="AUTH_LDAP_VERIFY_CERTS")
    auth_ldap_timeout_seconds: float = Field(default=5.0, alias="AUTH_LDAP_TIMEOUT_SECONDS")
    auth_ldap_group_role_map: str = Field(default="", alias="AUTH_LDAP_GROUP_ROLE_MAP")

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
    url_resolution_enabled: bool = Field(default=True, alias="URL_RESOLUTION_ENABLED")
    url_resolution_timeout_seconds: float = Field(default=4.0, alias="URL_RESOLUTION_TIMEOUT_SECONDS")
    url_resolution_max_hops: int = Field(default=5, alias="URL_RESOLUTION_MAX_HOPS")
    url_resolution_max_urls: Optional[int] = Field(default=None, alias="URL_RESOLUTION_MAX_URLS")
    url_resolution_user_agent: str = Field(default="Triagent URL Resolver/0.1", alias="URL_RESOLUTION_USER_AGENT")
    url_resolution_verify_tls: bool = Field(default=True, alias="URL_RESOLUTION_VERIFY_TLS")

    def cors_origins_list(self) -> List[str]:
        if not self.cors_origins:
            return []
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    def ldap_group_role_map_dict(self) -> dict[str, list[str]]:
        raw = (self.auth_ldap_group_role_map or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("AUTH_LDAP_GROUP_ROLE_MAP must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("AUTH_LDAP_GROUP_ROLE_MAP must be a JSON object")

        normalized: dict[str, list[str]] = {}
        for key, value in parsed.items():
            group_key = str(key).strip()
            if not group_key:
                continue
            if isinstance(value, str):
                roles = [value]
            elif isinstance(value, list):
                roles = value
            else:
                raise ValueError("AUTH_LDAP_GROUP_ROLE_MAP values must be strings or lists")

            cleaned_roles = sorted({str(item).strip().upper() for item in roles if str(item).strip()})
            if not cleaned_roles:
                continue
            normalized[group_key.lower()] = cleaned_roles
        return normalized


@lru_cache
def get_settings() -> Settings:
    return Settings()
