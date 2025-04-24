import pytest

from mozilla_django_oidc_db.models import (
    OIDCConfig,
    OIDCProviderConfig,
    UserInformationClaimsSources,
)

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


@pytest.fixture()
def multiple_configs_yml():
    return "tests/setupconfig/files/multiple_configs.yml"


@pytest.fixture()
def missing_identifier_yml():
    return "tests/setupconfig/files/missing_identifier.yml"


@pytest.fixture()
def multiple_providers_yml():
    return "tests/setupconfig/files/multiple_providers.yml"


@pytest.fixture()
def custom_options_yml():
    return "tests/setupconfig/files/custom_options.yml"


@pytest.fixture
def set_config_to_non_default_values():
    """
    Set the current config to non-default values.
    """
    config_provider = OIDCProviderConfig.objects.create(
        identifier="test-admit-oidc-provider",
        # Will be always overwritten
        oidc_op_authorization_endpoint="http://localhost:8080/whatever",
        oidc_op_token_endpoint="http://localhost:8080/whatever",
        oidc_op_user_endpoint="http://localhost:8080/whatever",
        # Set some non-default values
        oidc_op_discovery_endpoint="http://localhost:8080/whatever",
        oidc_op_jwks_endpoint="http://localhost:8080/whatever",
    )
    config, _ = OIDCConfig.objects.update_or_create(
        identifier="test-admin-oidc",
        defaults={
            # Will be always overwritten
            "oidc_rp_client_id": "different-client-id",
            "oidc_rp_client_secret": "different-secret",
            # Set some non-default values
            "enabled": False,
            "oidc_provider_config": config_provider,
            "oidc_rp_scopes_list": [
                "not_open_id",
                "not_email",
                "not_profile",
                "not_extra_scope",
            ],
            "oidc_rp_sign_algo": "M1911",
            "oidc_rp_idp_sign_key": "name",
            "oidc_use_nonce": True,
            "oidc_nonce_size": 64,
            "oidc_state_size": 64,
            "userinfo_claims_source": UserInformationClaimsSources.userinfo_endpoint,
            "options": {
                "user_settings": {
                    "claim_mappings": {
                        "username": ["claim_title"],
                        "first_title": ["given_title"],
                    }
                },
                "group_settings": {
                    "claim_mapping": ["groups_claim_title"],
                    "sync": True,
                    "sync_pattern": "not_local.groups.*",
                    "make_users_staff": False,
                    "superuser_group_names": ["poweruser"],
                    "default_groups": ["OldAdmin", "OldUser"],
                },
            },
        },
    )

    assert len(config.options["group_settings"]["default_groups"]) == 2
