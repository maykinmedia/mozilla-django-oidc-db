"""
Test the OIDC Authenticaton Request flow with our custom views.
"""

from urllib.parse import parse_qs, urlsplit

from django.http import HttpRequest, HttpResponseRedirect
from django.urls import reverse

import pytest

from mozilla_django_oidc_db.constants import OIDC_ADMIN_CONFIG_IDENTIFIER
from mozilla_django_oidc_db.exceptions import OIDCProviderOutage
from mozilla_django_oidc_db.plugins import OIDCAdminPlugin
from mozilla_django_oidc_db.registry import register
from mozilla_django_oidc_db.tests.factories import OIDCClientFactory
from mozilla_django_oidc_db.typing import GetParams
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestInitView

from .conftest import auth_request_mark as auth_request, oidcconfig


@oidcconfig(oidc_op_authorization_endpoint="http://localhost:8080/openid-connect/auth")
def test_default_config_flow(filled_admin_config, client):
    start_url = reverse("oidc_authentication_init")
    assert start_url == "/oidc/authenticate/"

    response = client.get(start_url, {"next": "/admin/"})

    # check that the view redirects to the identity provider
    assert response.status_code == 302
    parsed_url = urlsplit(response.url)
    assert parsed_url.scheme == "http"
    assert parsed_url.netloc == "localhost:8080"
    assert parsed_url.path == "/openid-connect/auth"

    # introspect state
    state_key = parse_qs(parsed_url.query)["state"][0]
    state = client.session["oidc_states"][state_key]
    assert state["config_identifier"] == OIDC_ADMIN_CONFIG_IDENTIFIER
    # upstream library
    assert client.session["oidc_login_next"] == "/admin/"
    # our own addition
    assert client.session["oidc-db_redirect_next"] == "/admin/"


@oidcconfig(oidc_keycloak_idp_hint="keycloak-idp2")
def test_keycloak_idp_hint_via_config(filled_admin_config, settings, client):
    settings.OIDC_KEYCLOAK_IDP_HINT = "keycloak-idp1"
    start_url = reverse("oidc_authentication_init")

    response = client.get(start_url)

    assert response.status_code == 302
    parsed_url = urlsplit(response.url)

    query = parse_qs(parsed_url.query)
    assert query["kc_idp_hint"] == ["keycloak-idp2"]


@oidcconfig(check_op_availability=True)
def test_check_idp_availability_not_available(
    filled_admin_config, settings, client, requests_mock
):
    requests_mock.get("https://mock-oidc-provider:9999/oidc/auth", status_code=503)
    start_url = reverse("oidc_authentication_init")

    with pytest.raises(OIDCProviderOutage):
        client.get(start_url)


@oidcconfig(check_op_availability=True)
def test_check_idp_availability_available(
    filled_admin_config, settings, client, requests_mock
):
    requests_mock.get("https://mock-oidc-provider:9999/oidc/auth", status_code=400)
    start_url = reverse("oidc_authentication_init")

    response = client.get(start_url)

    assert response.status_code == 302


@oidcconfig(oidc_rp_scopes_list=["email"])
@auth_request
def test_overwrite_scope(dummy_config, auth_request):
    """Test whether the scopes specified in the configuration can be overwritten."""

    @register("test-extra-scope")
    class OIDCTestExtraParamsPlugin(OIDCAdminPlugin):
        def get_extra_params(
            self, request: HttpRequest, extra_params: GetParams
        ) -> GetParams:
            return {**extra_params, "scope": "not-email and-extra"}

    OIDCClientFactory.create(identifier="test-extra-scope")

    oidc_init = OIDCAuthenticationRequestInitView.as_view(identifier="test-extra-scope")
    redirect_response = oidc_init(auth_request)

    assert redirect_response.status_code == 302
    assert isinstance(redirect_response, HttpResponseRedirect)

    parsed_url = urlsplit(redirect_response.url)
    query = parse_qs(parsed_url.query)

    assert query["scope"] == ["not-email and-extra"]
