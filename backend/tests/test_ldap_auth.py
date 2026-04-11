import json

from app.core.config import Settings
from app.services.ldap_auth import ldap_group_identifiers, map_ldap_groups_to_roles


def test_ldap_group_identifiers_include_dn_and_cn():
    identifiers = ldap_group_identifiers("CN=Triagent-Admins,OU=Groups,DC=example,DC=internal")
    assert "cn=triagent-admins,ou=groups,dc=example,dc=internal" in identifiers
    assert "triagent-admins" in identifiers


def test_map_ldap_groups_to_roles_matches_full_dn_and_cn():
    mapping = {
        "triagent-admins": ["ADMIN"],
        "cn=triagent-analysts,ou=groups,dc=example,dc=internal": ["ANALYST"],
    }

    roles = map_ldap_groups_to_roles(
        [
            "CN=Triagent-Admins,OU=Groups,DC=example,DC=internal",
            "CN=Triagent-Analysts,OU=Groups,DC=example,DC=internal",
        ],
        mapping,
    )

    assert roles == ["ADMIN", "ANALYST"]


def test_settings_parses_ldap_group_role_map():
    settings = Settings(
        AUTH_LDAP_GROUP_ROLE_MAP=json.dumps(
            {
                "triagent-admins": "ADMIN",
                "triagent-reviewers": ["REVIEWER", "READ_ONLY"],
            }
        )
    )

    assert settings.ldap_group_role_map_dict() == {
        "triagent-admins": ["ADMIN"],
        "triagent-reviewers": ["READ_ONLY", "REVIEWER"],
    }
