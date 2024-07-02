from typing import Any

import pytest

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.config import lookup_config
from mozilla_django_oidc_db.middleware import SessionRefresh
from mozilla_django_oidc_db.models import OpenIDConnectConfig
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestView


@pytest.mark.parametrize(
    "setting",
    (
        "OIDC_RP_CLIENT_ID",
        "OIDC_RP_CLIENT_SECRET",
        "OIDC_RP_SIGN_ALGO",
        "OIDC_OP_JWKS_ENDPOINT",
        "OIDC_OP_TOKEN_ENDPOINT",
        "OIDC_OP_USER_ENDPOINT",
        "OIDC_RP_IDP_SIGN_KEY",
    ),
)
def test_backend_without_initialization_request_raises(setting: str):
    backend = OIDCAuthenticationBackend()

    with pytest.raises(AssertionError):
        getattr(backend, setting)


@pytest.mark.parametrize(
    "setting,expected",
    (
        ("OIDC_RP_CLIENT_ID", "testid"),
        ("OIDC_RP_CLIENT_SECRET", "secret"),
        ("OIDC_RP_SIGN_ALGO", "HS256"),
        ("OIDC_OP_JWKS_ENDPOINT", "http://some.endpoint/v1/jwks"),
        ("OIDC_OP_TOKEN_ENDPOINT", "http://some.endpoint/v1/token"),
        ("OIDC_OP_USER_ENDPOINT", "http://some.endpoint/v1/user"),
        ("OIDC_RP_IDP_SIGN_KEY", None),
    ),
)
@pytest.mark.oidcconfig(
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
def test_backend_reads_settings_from_model(
    dummy_config, callback_request, setting: str, expected: Any
):
    backend = OIDCAuthenticationBackend()
    backend.config_class = lookup_config(callback_request)

    value = getattr(backend, setting)

    assert value == expected


@pytest.mark.oidcconfig(
    enabled=True,
    oidc_rp_client_id="testid",
    oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
)
def test_view_settings_derived_from_model_oidc_enabled(
    dummy_config: OpenIDConnectConfig,
):
    view = OIDCAuthenticationRequestView()

    # verify that the settings are derived from OpenIDConnectConfig
    assert view.OIDC_RP_CLIENT_ID == "testid"
    assert view.OIDC_OP_AUTH_ENDPOINT == "http://some.endpoint/v1/auth"


@pytest.mark.oidcconfig(
    enabled=True,
    oidc_rp_client_id="testid",
    oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
)
def test_middleware_use_falsy_default(
    dummy_config: OpenIDConnectConfig,
):
    middleware = SessionRefresh(lambda x: x)

    # verify that the defaults are allowed
    assert middleware.OIDC_EXEMPT_URLS == []
