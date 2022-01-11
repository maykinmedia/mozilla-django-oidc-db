from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.contrib.sessions.middleware import SessionMiddleware
from django.http.response import HttpResponseRedirect
from django.test import RequestFactory

import pytest

from mozilla_django_oidc_db.middleware import SessionRefresh
from mozilla_django_oidc_db.models import OpenIDConnectConfig


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_sessionrefresh_oidc_not_enabled(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(enabled=False)

    request = RequestFactory().get("/")

    # Running the middleware should return None, since OIDC is disabled
    result = SessionRefresh(get_response=lambda: None).process_request(request)

    assert result is None


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_sessionrefresh_config_always_refreshed(mock_get_solo):
    """
    Middleware should refresh the config on every call of `process_request`
    """
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

    middleware = SessionRefresh(get_response=lambda: None)
    request = RequestFactory().get("/")
    SessionMiddleware().process_request(request)

    with patch(
        "mozilla_django_oidc_db.middleware.SessionRefresh.is_refreshable_url",
        return_value=True,
    ):
        with patch("mozilla_django_oidc.middleware.reverse", return_value="/callback"):
            result1 = middleware.process_request(request)

            # Update the config and call the middleware again (without reinstantiating)
            mock_get_solo.return_value = OpenIDConnectConfig(
                enabled=True,
                oidc_rp_client_id="some-other-id",
                oidc_rp_client_secret="secret",
                oidc_rp_sign_algo="HS256",
                oidc_rp_scopes_list=["openid", "email", "other_scope"],
                oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
                oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
                oidc_op_token_endpoint="http://some.endpoint/v1/token",
                oidc_op_user_endpoint="http://some.endpoint/v1/user",
            )
            result2 = middleware.process_request(request)

    assert isinstance(result1, HttpResponseRedirect)
    assert isinstance(result2, HttpResponseRedirect)

    parsed1 = parse_qs(urlparse(result1.url).query)
    assert parsed1["client_id"] == ["testid"]
    assert parsed1["scope"] == ["openid email"]

    parsed2 = parse_qs(urlparse(result2.url).query)
    assert parsed2["client_id"] == ["some-other-id"]
    assert parsed2["scope"] == ["openid email other_scope"]
