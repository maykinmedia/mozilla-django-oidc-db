from django.urls import reverse

import pytest

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
