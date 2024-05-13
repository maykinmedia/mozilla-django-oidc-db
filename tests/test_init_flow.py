"""
Test the OIDC Authenticaton Request flow with our custom views.
"""

from urllib.parse import parse_qs, urlsplit

from django.urls import reverse

import pytest


@pytest.mark.vcr
def test_default_config_flow(keycloak_config, settings, client):
    settings.OIDC_AUTHENTICATE_CLASS = (
        "mozilla_django_oidc_db.views.OIDCAuthenticationRequestView"
    )
    start_url = reverse("oidc_authentication_init")
    assert start_url == "/oidc/authenticate/"

    response = client.get(start_url, {"next": "/admin/"})

    # check that the view redirects to the identity provider
    assert response.status_code == 302
    parsed_url = urlsplit(response.url)
    assert parsed_url.scheme == "http"
    assert parsed_url.netloc == "localhost:8080"
    assert parsed_url.path == "/realms/test/protocol/openid-connect/auth"

    # introspect state
    state_key = parse_qs(parsed_url.query)["state"][0]
    state = client.session["oidc_states"][state_key]
    assert state["config_class"] == "mozilla_django_oidc_db.OpenIDConnectConfig"
    # upstream library
    assert client.session["oidc_login_next"] == "/admin/"
    # our own addition
    assert client.session["oidc-db_redirect_next"] == "/admin/"


@pytest.mark.vcr
def test_keycloak_idp_hint_via_settings(keycloak_config, settings, client):
    settings.OIDC_AUTHENTICATE_CLASS = (
        "mozilla_django_oidc_db.views.OIDCAuthenticationRequestView"
    )
    settings.OIDC_KEYCLOAK_IDP_HINT = "keycloak-idp1"
    start_url = reverse("oidc_authentication_init")

    response = client.get(start_url)

    assert response.status_code == 302
    parsed_url = urlsplit(response.url)

    query = parse_qs(parsed_url.query)
    assert query["kc_idp_hint"] == ["keycloak-idp1"]
