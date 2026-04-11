from __future__ import annotations

import secrets
import ssl
from dataclasses import dataclass

from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.core.config import Settings


class LdapConfigurationError(ValueError):
    pass


class LdapUnavailableError(RuntimeError):
    pass


@dataclass
class LdapAuthenticatedUser:
    username: str
    directory_dn: str
    email: str | None
    groups: list[str]


def normalize_ldap_group(value: str) -> str:
    return value.strip().lower()


def ldap_group_identifiers(group_dn: str) -> set[str]:
    identifiers = {normalize_ldap_group(group_dn)}
    first_segment = group_dn.split(",", 1)[0].strip()
    if "=" in first_segment:
        _, raw_value = first_segment.split("=", 1)
        cleaned = normalize_ldap_group(raw_value)
        if cleaned:
            identifiers.add(cleaned)
    return identifiers


def map_ldap_groups_to_roles(group_dns: list[str], group_role_map: dict[str, list[str]]) -> list[str]:
    mapped_roles: set[str] = set()
    for group_dn in group_dns:
        for identifier in ldap_group_identifiers(group_dn):
            mapped_roles.update(group_role_map.get(identifier, []))
    return sorted(mapped_roles)


class LdapAuthenticator:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _validate_settings(self) -> None:
        missing = []
        if not self.settings.auth_ldap_server_uri:
            missing.append("AUTH_LDAP_SERVER_URI")
        if not self.settings.auth_ldap_base_dn:
            missing.append("AUTH_LDAP_BASE_DN")
        if missing:
            raise LdapConfigurationError(f"Missing LDAP settings: {', '.join(missing)}")

    def _server(self) -> Server:
        validate = ssl.CERT_REQUIRED if self.settings.auth_ldap_verify_certs else ssl.CERT_NONE
        tls = Tls(validate=validate)
        return Server(
            self.settings.auth_ldap_server_uri,
            get_info=ALL,
            tls=tls,
            connect_timeout=self.settings.auth_ldap_timeout_seconds,
        )

    def _search_connection(self, server: Server) -> Connection:
        try:
            connection = Connection(
                server,
                user=self.settings.auth_ldap_bind_dn,
                password=self.settings.auth_ldap_bind_password,
                auto_bind=False,
                raise_exceptions=True,
                receive_timeout=self.settings.auth_ldap_timeout_seconds,
            )
            connection.open()
            if self.settings.auth_ldap_start_tls and not server.ssl:
                connection.start_tls()
            connection.bind()
            return connection
        except LDAPException as exc:
            raise LdapUnavailableError("Failed to connect to LDAP") from exc

    def _bind_as_user(self, server: Server, user_dn: str, password: str) -> None:
        try:
            connection = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=False,
                raise_exceptions=True,
                receive_timeout=self.settings.auth_ldap_timeout_seconds,
            )
            connection.open()
            if self.settings.auth_ldap_start_tls and not server.ssl:
                connection.start_tls()
            connection.bind()
            connection.unbind()
        except LDAPBindError:
            raise
        except LDAPException as exc:
            raise LdapUnavailableError("LDAP bind failed") from exc

    def authenticate(self, username: str, password: str) -> LdapAuthenticatedUser | None:
        self._validate_settings()
        clean_username = username.strip()
        clean_password = password.strip()
        if not clean_username or not clean_password:
            return None

        server = self._server()
        search_conn = self._search_connection(server)
        try:
            search_filter = self.settings.auth_ldap_user_filter.format(username=escape_filter_chars(clean_username))
            attrs = [self.settings.auth_ldap_email_attribute, self.settings.auth_ldap_group_attribute]
            found = search_conn.search(
                search_base=self.settings.auth_ldap_base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=2,
            )
            if not found or len(search_conn.entries) != 1:
                return None

            entry = search_conn.entries[0]
            user_dn = entry.entry_dn

            email = None
            if self.settings.auth_ldap_email_attribute in entry:
                email = entry[self.settings.auth_ldap_email_attribute].value
                if isinstance(email, list):
                    email = email[0] if email else None
                if email is not None:
                    email = str(email).strip() or None

            groups: list[str] = []
            if self.settings.auth_ldap_group_attribute in entry:
                raw_groups = entry[self.settings.auth_ldap_group_attribute].value
                if isinstance(raw_groups, list):
                    groups = [str(item).strip() for item in raw_groups if str(item).strip()]
                elif raw_groups:
                    groups = [str(raw_groups).strip()]
        finally:
            search_conn.unbind()

        self._bind_as_user(server, user_dn, clean_password)

        return LdapAuthenticatedUser(
            username=clean_username.strip().lower(),
            directory_dn=user_dn,
            email=email,
            groups=groups,
        )


def ldap_fallback_password() -> str:
    return f"ldap-only-{secrets.token_urlsafe(24)}"
