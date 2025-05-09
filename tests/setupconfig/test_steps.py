from django.contrib.auth.models import Group

import pytest
import requests
from django_setup_configuration.exceptions import (
    ConfigurationRunFailed,
    PrerequisiteFailed,
)
from django_setup_configuration.test_utils import execute_single_step

from mozilla_django_oidc_db.models import (
    OIDCClient,
    OIDCProvider,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.setup_configuration.steps import AdminOIDCConfigurationStep

from ..conftest import KEYCLOAK_BASE_URL


def assert_full_values(identifier):
    config = OIDCClient.objects.get(identifier=identifier)
    assert not config.enabled
    assert config.oidc_rp_client_id == "client-id"
    assert config.oidc_rp_client_secret == "secret"
    assert config.oidc_rp_scopes_list == [
        "open_id",
        "email",
        "profile",
        "extra_scope",
    ]
    assert config.oidc_rp_sign_algo == "RS256"
    assert config.oidc_rp_idp_sign_key == "key"
    assert config.oidc_provider.oidc_op_discovery_endpoint == ""
    assert (
        config.oidc_provider.oidc_op_jwks_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_provider.oidc_op_authorization_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_provider.oidc_op_token_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
    )
    assert (
        config.oidc_provider.oidc_op_user_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo"
    )
    assert config.options["user_settings"]["claim_mappings"]["username"] == [
        "claim_name"
    ]
    assert config.options["user_settings"]["claim_mappings"]["first_name"] == [
        "given_name"
    ]
    assert config.options["group_settings"]["claim_mapping"] == ["groups_claim_name"]
    assert not config.options["group_settings"]["sync"]
    assert config.options["group_settings"]["sync_pattern"] == "local.groups.*"
    assert config.options["group_settings"]["default_groups"] == [
        "local.groups.Admins",
        "local.groups.Read-only",
    ]
    assert config.options["group_settings"]["make_users_staff"]
    assert config.options["group_settings"]["superuser_group_names"] == ["superuser"]
    assert not config.oidc_provider.oidc_use_nonce
    assert config.oidc_provider.oidc_nonce_size == 48
    assert config.oidc_provider.oidc_state_size == 48
    assert config.oidc_provider.oidc_op_authorization_endpoint
    assert config.userinfo_claims_source == UserInformationClaimsSources.id_token


@pytest.mark.django_db
def test_configure_full(full_config_yml):

    # create groups so they can be found
    Group.objects.create(name="local.groups.Admins")
    Group.objects.create(name="local.groups.Read-only")

    # test if idempotent
    execute_single_step(AdminOIDCConfigurationStep, yaml_source=full_config_yml)
    assert_full_values(identifier="test-admin-oidc")

    execute_single_step(AdminOIDCConfigurationStep, yaml_source=full_config_yml)
    assert_full_values(identifier="test-admin-oidc")


@pytest.mark.django_db
def test_configure_overwrite(full_config_yml, set_config_to_non_default_values):

    # create groups so they can be found
    Group.objects.create(name="local.groups.Admins")
    Group.objects.create(name="local.groups.Read-only")

    config = OIDCClient.objects.get(identifier="test-admin-oidc")

    # assert different values
    assert not config.enabled
    assert config.oidc_rp_client_id == "different-client-id"
    assert config.oidc_rp_client_secret == "different-secret"
    assert config.oidc_rp_scopes_list == [
        "not_open_id",
        "not_email",
        "not_profile",
        "not_extra_scope",
    ]
    assert config.oidc_rp_sign_algo == "M1911"
    assert config.oidc_rp_idp_sign_key == "name"
    assert (
        config.oidc_provider.oidc_op_discovery_endpoint
        == "http://localhost:8080/whatever"
    )
    assert (
        config.oidc_provider.oidc_op_jwks_endpoint == "http://localhost:8080/whatever"
    )
    assert (
        config.oidc_provider.oidc_op_authorization_endpoint
        == "http://localhost:8080/whatever"
    )
    assert (
        config.oidc_provider.oidc_op_token_endpoint == "http://localhost:8080/whatever"
    )
    assert (
        config.oidc_provider.oidc_op_user_endpoint == "http://localhost:8080/whatever"
    )
    assert config.options["user_settings"]["claim_mappings"]["username"] == [
        "claim_title"
    ]
    assert config.options["group_settings"]["claim_mapping"] == ["groups_claim_title"]
    assert config.options["user_settings"]["claim_mappings"]["first_title"] == [
        "given_title"
    ]
    assert config.options["group_settings"]["sync"]
    assert config.options["group_settings"]["sync_pattern"] == "not_local.groups.*"
    assert config.options["group_settings"]["default_groups"] == [
        "OldAdmin",
        "OldUser",
    ]
    assert not config.options["group_settings"]["make_users_staff"]
    assert config.options["group_settings"]["superuser_group_names"] == ["poweruser"]
    assert not config.oidc_provider.oidc_use_nonce
    assert config.oidc_provider.oidc_nonce_size == 64
    assert config.oidc_provider.oidc_state_size == 64
    assert config.oidc_provider.oidc_token_use_basic_auth
    assert (
        config.userinfo_claims_source == UserInformationClaimsSources.userinfo_endpoint
    )

    execute_single_step(AdminOIDCConfigurationStep, yaml_source=full_config_yml)
    # assert values overwritten
    assert_full_values(identifier="test-admin-oidc")


@pytest.mark.django_db
def test_configure_use_defaults(set_config_to_non_default_values, default_config_yml):
    execute_single_step(AdminOIDCConfigurationStep, yaml_source=default_config_yml)

    config = OIDCClient.objects.get(identifier="test-admin-oidc")

    assert config.enabled
    assert config.oidc_rp_client_id == "client-id"
    assert config.oidc_rp_client_secret == "secret"
    assert config.oidc_rp_scopes_list == ["openid", "email", "profile"]
    assert config.oidc_rp_sign_algo == "RS256"
    assert config.oidc_rp_idp_sign_key == ""
    assert config.oidc_provider.oidc_op_discovery_endpoint == ""
    assert config.oidc_provider.oidc_op_jwks_endpoint == ""

    assert (
        config.oidc_provider.oidc_op_authorization_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_provider.oidc_op_token_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
    )
    assert (
        config.oidc_provider.oidc_op_user_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo"
    )
    assert config.options["group_settings"]["claim_mapping"] == ["roles"]
    assert config.options["user_settings"]["claim_mappings"] == {
        "username": ["sub"],
        "last_name": ["family_name"],
        "first_name": ["given_name"],
        "email": ["email"],
    }
    assert config.options["group_settings"]["sync"]
    assert config.options["group_settings"]["sync_pattern"] == "*"
    assert config.options["group_settings"]["default_groups"] == []
    assert not config.options["group_settings"]["make_users_staff"]
    assert config.options["group_settings"]["superuser_group_names"] == []
    assert config.oidc_provider.oidc_use_nonce
    assert config.oidc_provider.oidc_nonce_size == 32
    assert config.oidc_provider.oidc_state_size == 32
    assert not config.oidc_provider.oidc_token_use_basic_auth
    assert (
        config.userinfo_claims_source == UserInformationClaimsSources.userinfo_endpoint
    )


@pytest.mark.vcr
@pytest.mark.django_db
def test_configure_use_discovery_endpoint(discovery_endpoint_config_yml):
    execute_single_step(
        AdminOIDCConfigurationStep, yaml_source=discovery_endpoint_config_yml
    )

    config = OIDCClient.objects.get(identifier="test-admin-oidc")

    assert config.enabled
    assert config.oidc_provider.oidc_op_discovery_endpoint == KEYCLOAK_BASE_URL
    assert (
        config.oidc_provider.oidc_op_jwks_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_provider.oidc_op_authorization_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_provider.oidc_op_token_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
    )
    assert (
        config.oidc_provider.oidc_op_user_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo"
    )
    assert config.oidc_provider.oidc_use_nonce
    assert config.oidc_provider.oidc_nonce_size == 32
    assert config.oidc_provider.oidc_state_size == 32
    assert not config.oidc_provider.oidc_token_use_basic_auth


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mock_kwargs",
    (
        {"exc": requests.ConnectTimeout},
        {"exc": requests.ConnectionError},
        {"status_code": 404},
        {"status_code": 403},
        {"status_code": 500},
    ),
    ids=[
        "Connection Timeout",
        "Connection Error",
        "Status 404",
        "Status 403",
        "Status 500",
    ],
)
def test_configure_discovery_failure(
    requests_mock, discovery_endpoint_config_yml, mock_kwargs
):
    OIDCClient.objects.get_or_create(identifier="test-admin-oidc")

    requests_mock.get(
        f"{KEYCLOAK_BASE_URL}.well-known/openid-configuration",
        **mock_kwargs,
    )

    with pytest.raises(ConfigurationRunFailed):
        execute_single_step(
            AdminOIDCConfigurationStep, yaml_source=discovery_endpoint_config_yml
        )

    config = OIDCClient.objects.get(identifier="test-admin-oidc")
    assert not config.enabled
    assert config.oidc_provider is None


@pytest.mark.django_db
def test_configure_fails_without_identifier(missing_identifier_yml):
    with pytest.raises(PrerequisiteFailed) as excinfo:
        execute_single_step(
            AdminOIDCConfigurationStep, yaml_source=missing_identifier_yml
        )
    assert "oidc_db_config_admin_auth.items.0.identifier" in str(excinfo.value)


@pytest.mark.vcr
@pytest.mark.django_db
def test_multiple_providers_configured(multiple_providers_yml):
    execute_single_step(AdminOIDCConfigurationStep, yaml_source=multiple_providers_yml)

    provider_discovery = OIDCProvider.objects.get(identifier="test-provider-discovery")
    assert (
        provider_discovery.oidc_op_authorization_endpoint
        == "http://localhost:8080/realms/test/protocol/openid-connect/auth"
    )
    assert not provider_discovery.oidc_use_nonce
    assert provider_discovery.oidc_nonce_size == 64
    assert provider_discovery.oidc_state_size == 64
    assert provider_discovery.oidc_token_use_basic_auth

    provider_discovery = OIDCProvider.objects.get(identifier="test-provider-full")
    assert (
        provider_discovery.oidc_op_authorization_endpoint
        == "http://localhost:8080/realms/test/protocol/openid-connect/auth"
    )

    assert (
        OIDCClient.objects.get(identifier="test-oidc-1").oidc_provider.identifier
        == "test-provider-discovery"
    )
    assert (
        OIDCClient.objects.get(identifier="test-oidc-2").oidc_provider.identifier
        == "test-provider-discovery"
    )
    assert (
        OIDCClient.objects.get(identifier="test-oidc-3").oidc_provider.identifier
        == "test-provider-full"
    )
    assert not provider_discovery.oidc_use_nonce
    assert provider_discovery.oidc_nonce_size == 48
    assert provider_discovery.oidc_state_size == 48
    assert provider_discovery.oidc_token_use_basic_auth


@pytest.mark.django_db
def test_custom_options(custom_options_yml):
    execute_single_step(AdminOIDCConfigurationStep, yaml_source=custom_options_yml)

    config = OIDCClient.objects.get(identifier="test-admin-oidc")

    assert config.options["test"] == "test"
    assert config.options["this"]["is"] == "a nested option!"
