from django.urls import reverse

import pytest

from mozilla_django_oidc_db.models import (
    OpenIDConnectConfig,
    UserInformationClaimsSources,
)

from .utils import keycloak_login

KEYCLOAK_BASE_URL = "http://localhost:8080/realms/test/"


@pytest.mark.vcr
def test_client_id_secret_full_flow(
    keycloak_config, mock_state_and_nonce, client, django_user_model, vcr
):
    login_url = reverse("login")
    django_login_response = client.get(login_url)
    assert django_login_response.status_code, 302

    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"])

    # complete the login flow on our end
    callback_response = client.get(redirect_uri)

    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    # a user was created
    assert django_user_model.objects.count() == 1

    # check that the token request was performed as expected
    token_request = next(
        req
        for req in vcr.requests
        if req.uri == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
        and req.method == "POST"
    )
    assert token_request is not None
    assert b"client_id=testid" in token_request.body
    assert b"secret=7DB3KUAAizYCcmZufpHRVOcD0TOkNO3I" in token_request.body
    assert "Authorization" not in token_request.headers


@pytest.mark.vcr
def test_credentials_in_basic_auth_header(
    keycloak_config: OpenIDConnectConfig,
    mock_state_and_nonce,
    client,
    django_user_model,
    vcr,
):
    keycloak_config.oidc_token_use_basic_auth = True
    keycloak_config.save()

    django_login_response = client.get(reverse("login"))
    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"])

    # complete the login flow on our end
    callback_response = client.get(redirect_uri)
    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    # check that the token request was performed as expected
    token_request = next(
        req
        for req in vcr.requests
        if req.uri == f"{KEYCLOAK_BASE_URL}protocol/openid-connect/token"
        and req.method == "POST"
    )
    assert token_request is not None

    assert "Authorization" in token_request.headers
    bits = token_request.headers["Authorization"].split(" ")
    assert len(bits) == 2
    assert bits[0] == "Basic"

    assert b"client_id=testid" in token_request.body
    assert b"secret=" not in token_request.body


@pytest.mark.vcr
def test_return_jwt_from_userinfo_endpoint(
    keycloak_config: OpenIDConnectConfig,
    mock_state_and_nonce,
    client,
    django_user_model,
):
    # Set up client configured to return JWT from userinfo endpoint instead of plain
    # JSON. Credentials from ``docker/import`` realm export.
    keycloak_config.oidc_rp_client_id = "test-userinfo-jwt"
    keycloak_config.oidc_rp_client_secret = "ktGlGUELd1FR7dTXc84L7dJzUTjCtw9S"
    keycloak_config.userinfo_claims_source = (
        UserInformationClaimsSources.userinfo_endpoint
    )
    keycloak_config.save()

    django_login_response = client.get(reverse("login"))
    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"])

    # complete the login flow on our end
    callback_response = client.get(redirect_uri)
    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    # a user was created
    assert django_user_model.objects.count() == 1
