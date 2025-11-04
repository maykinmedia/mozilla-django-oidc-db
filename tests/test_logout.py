from django.test import Client
from django.urls import reverse

import pytest
from requests import Session

from mozilla_django_oidc_db.models import OIDCClient
from mozilla_django_oidc_db.tests.utils import keycloak_login
from mozilla_django_oidc_db.utils import do_op_logout

from .conftest import oidcconfig


@pytest.fixture
def kc_session(
    settings,
    keycloak_config,
    mock_state_and_nonce,
    client,
    django_user_model,
    vcr,
):
    settings.OIDC_STORE_ID_TOKEN = True
    session = Session()

    login_url = reverse("login-keycloak")
    django_login_response = client.get(login_url)
    assert django_login_response.status_code == 302

    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"], session=session)

    # complete the login flow on our end
    callback_response = client.get(redirect_uri)

    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    # a user was created
    assert django_user_model.objects.count() == 1

    # assert that we are logged in to keycloak
    django_login_response2 = client.get(login_url)

    kc_response = session.get(django_login_response2["Location"], allow_redirects=False)
    assert kc_response.status_code == 302
    assert kc_response.headers["Location"].startswith("http://testserver")

    yield (client, session)

    session.close()


@pytest.mark.vcr
@oidcconfig(oidc_op_logout_endpoint="")
def test_logout_without_endpoint_configured(
    keycloak_config: OIDCClient,
    kc_session: tuple[Client, Session],
):
    client, session = kc_session

    do_op_logout(keycloak_config, id_token=client.session["oidc_id_token"])

    # check that we are still authenticated in keycloak
    login_url = reverse("login-keycloak")
    django_login_response = client.get(login_url)
    kc_response = session.get(django_login_response["Location"], allow_redirects=False)

    assert kc_response.status_code == 302
    assert kc_response.headers["Location"].startswith("http://testserver")


@pytest.mark.vcr
def test_logout_with_logout_endpoint_configured(
    keycloak_config: OIDCClient,
    kc_session: tuple[Client, Session],
):
    assert keycloak_config.oidc_provider.oidc_op_logout_endpoint
    client, session = kc_session

    do_op_logout(keycloak_config, id_token=client.session["oidc_id_token"])

    # check that we are still authenticated in keycloak
    login_url = reverse("login-keycloak")
    django_login_response = client.get(login_url)
    kc_response = session.get(django_login_response["Location"], allow_redirects=False)

    assert kc_response.status_code == 200, "Did not end up on Keycloak's login page"
    assert kc_response.headers["Content-Type"].startswith("text/html")


@oidcconfig(oidc_op_logout_endpoint="https://example.com/oidc/logout")
def test_logout_response_has_redirect(dummy_config: OIDCClient, requests_mock):
    requests_mock.post(
        "https://example.com/oidc/logout",
        status_code=302,
        headers={"Location": "http://testserver/endpoint-that-does-not-exist"},
    )

    try:
        do_op_logout(dummy_config, id_token="dummy-id-token")
    except Exception:
        pytest.fail("Logout should not crash")
