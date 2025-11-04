from django.urls import reverse

import pytest
import requests

from mozilla_django_oidc_db.models import (
    OIDCClient,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.tests.utils import keycloak_login

from .conftest import oidcconfig

KEYCLOAK_BASE_URL = "http://localhost:8080/realms/test/"


@pytest.mark.vcr
def test_client_id_secret_full_flow(
    keycloak_config, mock_state_and_nonce, client, django_user_model, vcr
):
    login_url = reverse("login-keycloak")
    django_login_response = client.get(login_url)
    assert django_login_response.status_code == 302

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
    keycloak_config: OIDCClient,
    mock_state_and_nonce,
    client,
    django_user_model,
    vcr,
):
    assert keycloak_config.oidc_provider

    provider = keycloak_config.oidc_provider
    provider.oidc_token_use_basic_auth = True
    provider.save()

    django_login_response = client.get(reverse("login-keycloak"))
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
@oidcconfig(
    # Set up client configured to return JWT from userinfo endpoint instead of plain
    # JSON. Credentials from ``docker/import`` realm export.
    oidc_rp_client_id="test-userinfo-jwt",
    oidc_rp_client_secret="ktGlGUELd1FR7dTXc84L7dJzUTjCtw9S",
    userinfo_claims_source=UserInformationClaimsSources.userinfo_endpoint,
)
def test_return_jwt_from_userinfo_endpoint(
    keycloak_config: OIDCClient,
    mock_state_and_nonce,
    client,
    django_user_model,
):
    django_login_response = client.get(reverse("login-keycloak"))
    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"])

    # complete the login flow on our end
    callback_response = client.get(redirect_uri)
    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    # a user was created
    assert django_user_model.objects.count() == 1


@pytest.mark.vcr
@oidcconfig(extra_options={"make_users_staff": True})
def test_session_refresh(
    keycloak_config,
    settings,
    mock_state_and_nonce,
    client,
    django_user_model,
    vcr,
    mocker,
):
    session = requests.Session()
    settings.MIDDLEWARE = settings.MIDDLEWARE + [
        "mozilla_django_oidc_db.middleware.SessionRefresh"
    ]
    settings.OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS = 60
    login_url = reverse("login-keycloak")

    django_login_response = client.get(login_url)
    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"], session=session)
    # complete the login flow on our end
    callback_response = client.get(redirect_uri)

    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    admin_response = client.get("/admin/")

    # User was successfully logged in
    assert admin_response.status_code == 200

    # when the user refreshes the admin index, SessionRefresh should be called and
    # should redirect user to Keycloak
    mocker.patch("mozilla_django_oidc.middleware.time.time", lambda: 10**11)

    admin_response = client.get("/admin/")

    assert "/realms/test/protocol/openid-connect/auth" in admin_response["Location"]

    # Following the Keycloak response should redirect the user to the callback immediately,
    # because the user still has an active session with Keycloak
    keycloak_response = session.get(admin_response["Location"], allow_redirects=False)

    assert keycloak_response.status_code == 302
    assert "/oidc/callback/" in keycloak_response.headers["Location"]

    app_response = client.get(keycloak_response.headers["Location"])

    assert app_response.status_code == 302
    assert app_response.url == "/admin/"

    admin_response = client.get("/admin/")

    # User can reach the admin index again
    assert admin_response.status_code == 200
