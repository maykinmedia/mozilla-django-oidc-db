from django.contrib.auth.models import Group

import pytest
import requests
from django_setup_configuration.exceptions import ConfigurationRunFailed
from django_setup_configuration.test_utils import execute_single_step

from mozilla_django_oidc_db.models import (
    OpenIDConnectConfig,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.setup_configuration.steps import AdminOIDCConfigurationStep

from ..conftest import KEYCLOAK_BASE_URL
from .conftest import set_config_to_non_default_values


@pytest.fixture(autouse=True)
def clear_solo_cache():
    yield
    OpenIDConnectConfig.clear_cache()


def assert_full_values():
    config = OpenIDConnectConfig.get_solo()
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
def test_configure_full(full_config_yml):

    # create groups so they can be found
    Group.objects.create(name="local.groups.Admins")
    Group.objects.create(name="local.groups.Read-only")

    # test if idempotent
    execute_single_step(AdminOIDCConfigurationStep, yaml_source=full_config_yml)
    assert_full_values()

    execute_single_step(AdminOIDCConfigurationStep, yaml_source=full_config_yml)
    assert_full_values()


@pytest.mark.django_db
def test_configure_overwrite(full_config_yml, set_config_to_non_default_values):

    # create groups so they can be found
    Group.objects.create(name="local.groups.Admins")
    Group.objects.create(name="local.groups.Read-only")

    config = OpenIDConnectConfig.get_solo()

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
    assert config.oidc_op_discovery_endpoint == "http://localhost:8080/whatever"
    assert config.oidc_op_jwks_endpoint == "http://localhost:8080/whatever"
    assert config.oidc_op_authorization_endpoint == "http://localhost:8080/whatever"
    assert config.oidc_op_token_endpoint == "http://localhost:8080/whatever"
    assert config.oidc_op_user_endpoint == "http://localhost:8080/whatever"
    assert config.username_claim == ["claim_title"]
    assert config.groups_claim == ["groups_claim_title"]
    assert config.claim_mapping == {"first_title": ["given_title"]}
    assert config.sync_groups
    assert config.sync_groups_glob_pattern == "not_local.groups.*"
    assert set(group.name for group in config.default_groups.all()) == {
        "OldAdmin",
        "OldUser",
    }
    assert not config.make_users_staff
    assert config.superuser_group_names == ["poweruser"]
    assert config.oidc_use_nonce
    assert config.oidc_nonce_size == 64
    assert config.oidc_state_size == 64
    assert (
        config.userinfo_claims_source == UserInformationClaimsSources.userinfo_endpoint
    )

    execute_single_step(AdminOIDCConfigurationStep, yaml_source=full_config_yml)
    # assert values overwritten
    assert_full_values()


@pytest.mark.django_db
def test_configure_use_defaults(set_config_to_non_default_values, default_config_yml):
    execute_single_step(AdminOIDCConfigurationStep, yaml_source=default_config_yml)

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
def test_configure_use_discovery_endpoint(discovery_endpoint_config_yml):
    execute_single_step(
        AdminOIDCConfigurationStep, yaml_source=discovery_endpoint_config_yml
    )

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
    requests_mock.get(
        f"{KEYCLOAK_BASE_URL}.well-known/openid-configuration",
        **mock_kwargs,
    )

    with pytest.raises(ConfigurationRunFailed):
        execute_single_step(
            AdminOIDCConfigurationStep, yaml_source=discovery_endpoint_config_yml
        )

    config = OpenIDConnectConfig.get_solo()
    assert not config.enabled
    assert config.oidc_op_discovery_endpoint == ""


@pytest.mark.django_db
def test_sync_groups_is_false(no_sync_groups_config_yml):
    # create groups so they can be found
    super_admin = Group.objects.create(name="SuperAdmins")

    result = execute_single_step(
        AdminOIDCConfigurationStep, yaml_source=no_sync_groups_config_yml
    )

    assert not result.config_model.sync_groups
    assert result.config_model.default_groups == ["SuperAdmins", "NormalUsers"]

    config = OpenIDConnectConfig.get_solo()
    assert config.default_groups.all().count() == 1
    assert config.default_groups.get() == super_admin


@pytest.mark.django_db
def test_sync_groups_is_true(sync_groups_config_yml):
    # create groups so they can be found
    super_admin = Group.objects.create(name="local.groups.SuperAdmins")
    weird_admin = Group.objects.create(name="local.WeirdAdmins")

    result = execute_single_step(
        AdminOIDCConfigurationStep, yaml_source=sync_groups_config_yml
    )

    assert result.config_model.sync_groups
    assert result.config_model.default_groups == [
        "local.groups.SuperAdmins",
        "local.WeirdAdmins",
        "local.groups.NormalUsers",
        "local.WeirdUsers",
    ]
    assert result.config_model.sync_groups_glob_pattern == "local.groups.*"

    config = OpenIDConnectConfig.get_solo()
    assert config.default_groups.all().count() == 3
    assert super_admin in config.default_groups.all()
    assert weird_admin in config.default_groups.all()
    assert config.default_groups.all().filter(name="local.groups.NormalUsers").exists()
    # Does not match glob, is not created
    assert not config.default_groups.all().filter(name="local.WeirdUsers").exists()
