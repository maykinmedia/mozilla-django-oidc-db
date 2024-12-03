import pytest

from mozilla_django_oidc_db.models import (
    OpenIDConnectConfig,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.utils import get_groups_by_name

"""
Key cloak credentials are setup for the keycloak docker-compose.yml.

`oidc_rp_client_id` and `oidc_rp_client_secret` are taken from the keycloak fixture
in /docker/import/test-reaml.json

See more info in /docker/README.md

"""


# Test files
@pytest.fixture()
def full_config_yml():
    return "tests/setupconfig/files/full_setup.yml"


@pytest.fixture()
def default_config_yml():
    return "tests/setupconfig/files/defaults.yml"


@pytest.fixture()
def discovery_endpoint_config_yml():
    return "tests/setupconfig/files/discovery.yml"


@pytest.fixture()
def no_sync_groups_config_yml():
    return "tests/setupconfig/files/no_sync_groups.yml"


@pytest.fixture()
def sync_groups_config_yml():
    return "tests/setupconfig/files/sync_groups.yml"


@pytest.fixture
def set_config_to_non_default_values():
    """
    Set the current config to non-default values.
    """

    config = OpenIDConnectConfig.get_solo()

    # Will be always overwritten
    config.oidc_rp_client_id = "different-client-id"
    config.oidc_rp_client_secret = "different-secret"
    config.oidc_op_authorization_endpoint = "http://localhost:8080/whatever"
    config.oidc_op_token_endpoint = "http://localhost:8080/whatever"
    config.oidc_op_user_endpoint = "http://localhost:8080/whatever"

    # Set some non-default values
    config.oidc_op_discovery_endpoint = "http://localhost:8080/whatever"
    config.enabled = False

    config.oidc_rp_scopes_list = [
        "not_open_id",
        "not_email",
        "not_profile",
        "not_extra_scope",
    ]
    config.oidc_rp_sign_algo = "M1911"
    config.oidc_rp_idp_sign_key = "name"
    config.oidc_op_jwks_endpoint = "http://localhost:8080/whatever"
    config.username_claim = ["claim_title"]
    config.groups_claim = ["groups_claim_title"]
    config.claim_mapping = {"first_title": ["given_title"]}
    config.sync_groups = True
    config.sync_groups_glob_pattern = "not_local.groups.*"

    config.make_users_staff = False
    config.superuser_group_names = ["poweruser"]
    config.oidc_use_nonce = True
    config.oidc_nonce_size = 64
    config.oidc_state_size = 64
    config.userinfo_claims_source = UserInformationClaimsSources.userinfo_endpoint

    config.default_groups.set(get_groups_by_name(["OldAdmin", "OldUser"], "*", True))

    config.save()

    assert config.default_groups.all().count() == 2
