from io import StringIO

from django.core.management import CommandError, call_command

import pytest
import requests
from django_setup_configuration.exceptions import ConfigurationRunFailed

from mozilla_django_oidc_db.models import (
    OpenIDConnectConfig,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.setup_configuration.steps import AdminOIDCConfigurationStep

from ..conftest import KEYCLOAK_BASE_URL


@pytest.fixture(autouse=True)
def clear_solo_cache():
    yield
    OpenIDConnectConfig.clear_cache()


@pytest.mark.django_db
def test_configure(setup_config_full_model):
    step = AdminOIDCConfigurationStep()
    step.execute(setup_config_full_model)

    config = OpenIDConnectConfig.get_solo()

    assert config.enabled
    assert config.oidc_rp_client_id == "client-id"
    assert config.oidc_rp_client_secret == "secret"
    assert config.oidc_rp_scopes_list == ["open_id", "email", "profile", "extra_scope"]
    assert config.oidc_rp_sign_algo == "RS256"
    assert config.oidc_rp_idp_sign_key == "key"
    assert config.oidc_op_discovery_endpoint == ""
    assert (
        config.oidc_op_jwks_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_op_authorization_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo"
    )
    assert config.username_claim == ["claim_name"]
    assert config.groups_claim == ["groups_claim_name"]
    assert config.claim_mapping == {"first_name": ["given_name"]}
    assert not config.sync_groups
    assert config.sync_groups_glob_pattern == "local.groups.*"
    assert set(group.name for group in config.default_groups.all()) == {
        "local.groups.Admins",
        "local.groups.Read-only",
    }
    assert config.make_users_staff
    assert config.superuser_group_names == ["superuser"]
    assert not config.oidc_use_nonce
    assert config.oidc_nonce_size == 48
    assert config.oidc_state_size == 48
    assert config.userinfo_claims_source == UserInformationClaimsSources.id_token


@pytest.mark.django_db
def test_required_settings():
    output = StringIO()
    err = StringIO()
    with pytest.raises(CommandError) as command_error:
        call_command(
            "setup_configuration",
            yaml_file="tests/setupconfig/files/empty.yml",
            stdout=output,
            stderr=err,
        )

    assert "Prerequisites for configuration are not fulfilled:" in str(
        command_error.value
    )

    assert "ADMIN_OIDC.oidc_rp_client_id" in str(command_error.value)
    assert "ADMIN_OIDC.oidc_rp_client_secret" in str(command_error.value)
    assert "ADMIN_OIDC.endpoint_config" in str(command_error.value)

    config = OpenIDConnectConfig.get_solo()
    assert not config.enabled


@pytest.mark.django_db
def test_partial_endpoints_provided():
    """
    Test what if only one endpoint (not discovery) is provided
    """
    output = StringIO()
    err = StringIO()
    with pytest.raises(CommandError) as command_error:
        call_command(
            "setup_configuration",
            yaml_file="tests/setupconfig/files/partial_endpoints.yml",
            stdout=output,
            stderr=err,
        )

    assert "Prerequisites for configuration are not fulfilled:" in str(
        command_error.value
    )

    assert "ADMIN_OIDC.endpoint_config.all.oidc_op_token_endpoint" in str(
        command_error.value
    )
    assert "ADMIN_OIDC.endpoint_config.all.oidc_op_user_endpoint" in str(
        command_error.value
    )

    config = OpenIDConnectConfig.get_solo()
    assert not config.enabled


@pytest.mark.django_db
def test_enable_setting():
    output = StringIO()
    err = StringIO()
    with pytest.raises(CommandError) as command_error:
        call_command(
            "setup_configuration",
            yaml_file="tests/setupconfig/files/discovery_disabled.yml",
            stdout=output,
            stderr=err,
        )

    assert "No steps enabled, aborting." in str(command_error.value)

    config = OpenIDConnectConfig.get_solo()
    assert not config.enabled


@pytest.mark.django_db
def test_configure_use_defaults(setup_config_defaults_model):
    step = AdminOIDCConfigurationStep()
    step.execute(setup_config_defaults_model)

    config = OpenIDConnectConfig.get_solo()

    assert config.enabled
    assert config.oidc_rp_client_id == "client-id"
    assert config.oidc_rp_client_secret == "secret"
    assert config.oidc_rp_scopes_list == ["openid", "email", "profile"]
    assert config.oidc_rp_sign_algo == "HS256"
    assert config.oidc_rp_idp_sign_key == ""
    assert config.oidc_op_discovery_endpoint == ""
    assert config.oidc_op_jwks_endpoint == ""

    assert (
        config.oidc_op_authorization_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo"
    )
    assert config.username_claim == ["sub"]
    assert config.groups_claim == ["roles"]
    assert config.claim_mapping == {
        "last_name": ["family_name"],
        "first_name": ["given_name"],
        "email": ["email"],
    }
    assert config.sync_groups
    assert config.sync_groups_glob_pattern == "*"
    assert config.default_groups.all().count() == 0
    assert not config.make_users_staff
    assert config.superuser_group_names == []
    assert config.oidc_use_nonce
    assert config.oidc_nonce_size == 32
    assert config.oidc_state_size == 32
    assert (
        config.userinfo_claims_source == UserInformationClaimsSources.userinfo_endpoint
    )


@pytest.mark.vcr
@pytest.mark.django_db
def test_configure_use_discovery_endpoint(setup_config_discovery_model):
    step = AdminOIDCConfigurationStep()
    step.execute(setup_config_discovery_model)

    config = OpenIDConnectConfig.get_solo()

    assert config.enabled
    assert config.oidc_op_discovery_endpoint == KEYCLOAK_BASE_URL
    assert (
        config.oidc_op_jwks_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_op_authorization_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/userinfo"
    )


@pytest.mark.django_db
def test_configure_discovery_failure(requests_mock, setup_config_discovery_model):
    mock_kwargs = (
        {"exc": requests.ConnectTimeout},
        {"exc": requests.ConnectionError},
        {"status_code": 404},
        {"status_code": 403},
        {"status_code": 500},
    )
    for mock_config in mock_kwargs:
        requests_mock.get(
            f"{KEYCLOAK_BASE_URL}.well-known/openid-configuration",
            **mock_config,
        )

        with pytest.raises(ConfigurationRunFailed):
            AdminOIDCConfigurationStep().execute(setup_config_discovery_model)

        assert not OpenIDConnectConfig.get_solo().enabled
