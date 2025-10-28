from django.test import Client
from django.urls import reverse

import pytest
from requests import Session

from mozilla_django_oidc_db.models import OIDCClient
from mozilla_django_oidc_db.tests.utils import keycloak_login

from .conftest import oidcconfig


@pytest.mark.vcr
@oidcconfig(extra_options={"make_users_staff": True})
def test_use_config_class_from_state_over_config_class_from_session(
    keycloak_config: OIDCClient,
    dummy_config: OIDCClient,
    mock_state_and_nonce,
    client: Client,
):
    """
    When using two different OIDC configs, ensure that their state doesn't get mixed up.

    First, we authenticate in the django admin, this is the config that uses the
    session refresh, and the config set up through fixtures.

    Second, we have another OIDC config that uses another provider. The state of the
    first authentication may not affect the second authentication flow.
    """
    session = Session()
    # login to the admin
    login_url = reverse("login-keycloak")
    django_login_response = client.get(login_url)
    redirect_uri = keycloak_login(django_login_response["Location"], session=session)
    callback_response = client.get(redirect_uri, follow=True)
    # sanity check
    assert callback_response.wsgi_request.path == reverse("admin:index")

    # set up an authentication flow & state with another config - all the credentials
    # are otherwise the same - the only difference is where the callback redirects after
    # succesful authentication
    login_url2 = reverse("login-keycloak-custom")
    django_login_response2 = client.get(login_url2)
    # we expect to still be authenticated in the keycloak session, so we can fetch the
    # URL directly - and perform a sanity check!
    _response = session.get(django_login_response2["Location"], allow_redirects=False)
    redirect_uri2 = _response.headers["Location"]
    assert redirect_uri2.startswith("http://testserver/")
    callback_response2 = client.get(redirect_uri2, follow=True)
    assert callback_response2.wsgi_request.path == "/custom-success-url"
