import pytest

from mozilla_django_oidc_db.models import UserInformationClaimsSources

from ..conftest import KEYCLOAK_BASE_URL

"""
Key cloak credentials are setup for the keycloak docker-compose.yml.

`oidc_rp_client_id` and `oidc_rp_client_secret` are taken from the keycloak fixture
in /docker/import/test-reaml.json

See more info in /docker/README.md

"""


@pytest.fixture
def setup_config_discovery(settings):
    settings.OIDC_DB_SETUP_CONFIG_ADMIN_AUTH = {
        "oidc_rp_client_id": "testid",
        "oidc_rp_client_secret": "7DB3KUAAizYCcmZufpHRVOcD0TOkNO3I",
        "oidc_op_discovery_endpoint": KEYCLOAK_BASE_URL,
    }


@pytest.fixture
def setup_config_defaults(settings):
    settings.OIDC_DB_SETUP_CONFIG_ADMIN_AUTH = {
        "oidc_rp_client_id": "client-id",
        "oidc_rp_client_secret": "secret",
        "oidc_op_authorization_endpoint": f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth",
        "oidc_op_token_endpoint": f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token",
        "oidc_op_user_endpoint": f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo",
    }


@pytest.fixture
def setup_config_full(settings):

    settings.OIDC_DB_SETUP_CONFIG_ADMIN_AUTH = {
        "oidc_rp_client_id": "client-id",
        "oidc_rp_client_secret": "secret",
        "oidc_rp_scopes_list": ["open_id", "email", "profile", "extra_scope"],
        "oidc_rp_sign_algo": "RS256",
        "oidc_rp_idp_sign_key": "key",
        "oidc_op_discovery_endpoint": None,
        "oidc_op_jwks_endpoint": f"{KEYCLOAK_BASE_URL}protocol/openid-connect/certs",
        "oidc_op_authorization_endpoint": (
            f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
        ),
        "oidc_op_token_endpoint": f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token",
        "oidc_op_user_endpoint": f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo",
        "username_claim": ["claim_name"],
        "groups_claim": ["groups_claim_name"],
        "claim_mapping": {"first_name": ["given_name"]},
        "sync_groups": False,
        "sync_groups_glob_pattern": "local.groups.*",
        "default_groups": ["Admins", "Read-only"],
        "make_users_staff": True,
        "superuser_group_names": ["superuser"],
        "oidc_use_nonce": False,
        "oidc_nonce_size": 48,
        "oidc_state_size": 48,
        "userinfo_claims_source": UserInformationClaimsSources.id_token,
    }
