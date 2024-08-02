from django.conf import settings as django_settings
from django.test import override_settings

import pytest
import requests
from django_setup_configuration.exceptions import ConfigurationRunFailed

from mozilla_django_oidc_db.models import (
    OpenIDConnectConfig,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.setupconfig.boostrap import AdminOIDCConfigurationStep

IDENTITY_PROVIDER = django_settings.IDENTITY_PROVIDER


@pytest.mark.django_db
def test_configure():
    AdminOIDCConfigurationStep().configure()

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
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_op_authorization_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/userinfo"
    )
    assert config.username_claim == ["claim_name"]
    assert config.groups_claim == ["groups_claim_name"]
    assert config.claim_mapping == {"first_name": "given_name"}
    assert not config.sync_groups
    assert config.sync_groups_glob_pattern == "local.groups.*"
    assert list(group.name for group in config.default_groups.all()) == [
        "Admins",
        "Read-only",
    ]
    assert config.make_users_staff
    assert config.superuser_group_names == ["superuser"]
    assert not config.oidc_use_nonce
    assert config.oidc_nonce_size == 48
    assert config.oidc_state_size == 48
    assert config.userinfo_claims_source == UserInformationClaimsSources.id_token


@override_settings(
    ADMIN_OIDC_OIDC_RP_SCOPES_LIST=None,
    ADMIN_OIDC_OIDC_RP_SIGN_ALGO=None,
    ADMIN_OIDC_OIDC_RP_IDP_SIGN_KEY=None,
    ADMIN_OIDC_USERNAME_CLAIM=None,
    ADMIN_OIDC_CLAIM_MAPPING=None,
    ADMIN_OIDC_SYNC_GROUPS=None,
    ADMIN_OIDC_SYNC_GROUPS_GLOB_PATTERN=None,
    ADMIN_OIDC_MAKE_USERS_STAFF=None,
    ADMIN_OIDC_OIDC_USE_NONCE=None,
    ADMIN_OIDC_OIDC_NONCE_SIZE=None,
    ADMIN_OIDC_OIDC_STATE_SIZE=None,
    ADMIN_OIDC_OIDC_EXEMPT_URLS=None,
    ADMIN_OIDC_USERINFO_CLAIMS_SOURCE=None,
)
@pytest.mark.django_db
def test_configure_use_defaults():

    AdminOIDCConfigurationStep().configure()

    config = OpenIDConnectConfig.get_solo()

    assert config.enabled
    assert config.oidc_rp_client_id == "client-id"
    assert config.oidc_rp_client_secret == "secret"
    assert config.oidc_rp_scopes_list == ["openid", "email", "profile"]
    assert config.oidc_rp_sign_algo == "HS256"
    assert config.oidc_rp_idp_sign_key == ""
    assert config.oidc_op_discovery_endpoint == ""
    assert (
        config.oidc_op_jwks_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_op_authorization_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/userinfo"
    )
    assert config.username_claim == ["sub"]
    assert config.groups_claim == ["groups_claim_name"]
    assert config.claim_mapping == {
        "last_name": ["family_name"],
        "first_name": ["given_name"],
    }
    assert config.sync_groups
    assert config.sync_groups_glob_pattern == "*"
    assert list(group.name for group in config.default_groups.all()) == [
        "Admins",
        "Read-only",
    ]
    assert not config.make_users_staff
    assert config.superuser_group_names == ["superuser"]
    assert config.oidc_use_nonce
    assert config.oidc_nonce_size == 32
    assert config.oidc_state_size == 32
    assert (
        config.userinfo_claims_source == UserInformationClaimsSources.userinfo_endpoint
    )


@pytest.fixture
def discovery_endpoint_response():

    return {
        "issuer": IDENTITY_PROVIDER,
        "authorization_endpoint": f"{IDENTITY_PROVIDER}protocol/openid-connect/auth",
        "token_endpoint": f"{IDENTITY_PROVIDER}protocol/openid-connect/token",
        "userinfo_endpoint": f"{IDENTITY_PROVIDER}protocol/openid-connect/userinfo",
        "end_session_endpoint": f"{IDENTITY_PROVIDER}protocol/openid-connect/logout",
        "jwks_uri": f"{IDENTITY_PROVIDER}protocol/openid-connect/certs",
    }


@override_settings(
    ADMIN_OIDC_OIDC_OP_DISCOVERY_ENDPOINT=IDENTITY_PROVIDER,
    ADMIN_OIDC_OIDC_OP_JWKS_ENDPOINT=None,
    ADMIN_OIDC_OIDC_OP_AUTHORIZATION_ENDPOINT=None,
    ADMIN_OIDC_OIDC_OP_TOKEN_ENDPOINT=None,
    ADMIN_OIDC_OIDC_OP_USER_ENDPOINT=None,
)
@pytest.mark.django_db
def test_configure_use_discovery_endpoint(requests_mock, discovery_endpoint_response):
    requests_mock.get(
        f"{IDENTITY_PROVIDER}.well-known/openid-configuration",
        json=discovery_endpoint_response,
    )

    AdminOIDCConfigurationStep().configure()

    config = OpenIDConnectConfig.get_solo()

    assert config.enabled
    assert config.oidc_op_discovery_endpoint == IDENTITY_PROVIDER
    assert (
        config.oidc_op_jwks_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/certs"
    )
    assert (
        config.oidc_op_authorization_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == f"{IDENTITY_PROVIDER}protocol/openid-connect/userinfo"
    )


@override_settings(
    ADMIN_OIDC_OIDC_OP_DISCOVERY_ENDPOINT=IDENTITY_PROVIDER,
    ADMIN_OIDC_OIDC_OP_JWKS_ENDPOINT=None,
    ADMIN_OIDC_OIDC_OP_AUTHORIZATION_ENDPOINT=None,
    ADMIN_OIDC_OIDC_OP_TOKEN_ENDPOINT=None,
    ADMIN_OIDC_OIDC_OP_USER_ENDPOINT=None,
)
@pytest.mark.django_db
def test_configure_failure(requests_mock):
    mock_kwargs = (
        {"exc": requests.ConnectTimeout},
        {"exc": requests.ConnectionError},
        {"status_code": 404},
        {"status_code": 403},
        {"status_code": 500},
    )
    for mock_config in mock_kwargs:
        requests_mock.get(
            f"{IDENTITY_PROVIDER}.well-known/openid-configuration",
            **mock_config,
        )

        with pytest.raises(ConfigurationRunFailed):
            AdminOIDCConfigurationStep().configure()

        assert not OpenIDConnectConfig.get_solo().enabled


@pytest.mark.skip(reason="Testing config for DigiD OIDC is not implemented yet")
def test_configuration_check_ok():
    raise NotImplementedError


@pytest.mark.skip(reason="Testing config for DigiD OIDC is not implemented yet")
def test_configuration_check_failures():
    raise NotImplementedError


@pytest.mark.django_db
def test_is_configured():
    config = AdminOIDCConfigurationStep()

    assert not config.is_configured()

    config.configure()

    assert config.is_configured()
