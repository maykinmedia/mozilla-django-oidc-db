from unittest.mock import patch

import pytest

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.middleware import SessionRefresh
from mozilla_django_oidc_db.models import OpenIDConnectConfig
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestView


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_settings_derived_from_model_oidc_not_enabled(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(enabled=False)

    backend = OIDCAuthenticationBackend()

    # verify that the settings are not set in __init__
    assert backend.OIDC_RP_CLIENT_ID is None
    assert backend.OIDC_RP_CLIENT_SECRET is None
    assert backend.OIDC_RP_SIGN_ALGO == "HS256"  # default from mozilla-django-oidc
    assert backend.OIDC_OP_JWKS_ENDPOINT is None
    assert backend.OIDC_OP_TOKEN_ENDPOINT is None
    assert backend.OIDC_OP_USER_ENDPOINT is None
    assert backend.OIDC_RP_IDP_SIGN_KEY is None


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_settings_derived_from_model_oidc_enabled(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
    )

    backend = OIDCAuthenticationBackend()

    # verify that the settings are derived from OpenIDConnectConfig
    assert backend.OIDC_RP_CLIENT_ID == "testid"
    assert backend.OIDC_RP_CLIENT_SECRET == "secret"
    assert backend.OIDC_RP_SIGN_ALGO == "HS256"
    assert backend.OIDC_OP_JWKS_ENDPOINT == "http://some.endpoint/v1/jwks"
    assert backend.OIDC_OP_TOKEN_ENDPOINT == "http://some.endpoint/v1/token"
    assert backend.OIDC_OP_USER_ENDPOINT == "http://some.endpoint/v1/user"
    assert backend.OIDC_RP_IDP_SIGN_KEY is None


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_view_settings_derived_from_model_oidc_enabled(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
    )

    view = OIDCAuthenticationRequestView()

    # verify that the settings are derived from OpenIDConnectConfig
    assert view.OIDC_RP_CLIENT_ID == "testid"
    assert view.OIDC_OP_AUTH_ENDPOINT == "http://some.endpoint/v1/auth"
