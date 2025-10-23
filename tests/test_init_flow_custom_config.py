"""
Test the init flow.
"""

from urllib.parse import parse_qs, urlsplit

from django.core.exceptions import DisallowedRedirect
from django.http import HttpResponseRedirect

import pytest

from mozilla_django_oidc_db.exceptions import OIDCProviderOutage
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestInitView

from .conftest import oidcconfig

pytestmark = [pytest.mark.django_db]

init_view = OIDCAuthenticationRequestInitView.as_view(
    identifier="test-oidc", allow_next_from_query=False
)


@oidcconfig(
    enabled=True,
    oidc_rp_client_id="fixed_client_id",
    oidc_rp_client_secret="supersecret",
    oidc_op_authorization_endpoint="https://example.com/oidc/auth",
)
def test_redirects_to_oidc_provider(dummy_config, auth_request):
    response = init_view(auth_request, return_url="/fixed-next")

    assert response.status_code == 302
    assert isinstance(response, HttpResponseRedirect)
    parsed_url = urlsplit(response.url)
    assert parsed_url.scheme == "https"
    assert parsed_url.netloc == "example.com"
    assert parsed_url.path == "/oidc/auth"

    # introspect state
    state_key = parse_qs(parsed_url.query)["state"][0]
    state = auth_request.session["oidc_states"][state_key]
    assert state["config_identifier"] == "test-oidc"
    # upstream library
    assert auth_request.session["oidc_login_next"] == "/fixed-next"
    # our own addition
    assert auth_request.session["oidc-db_redirect_next"] == "/fixed-next"


@oidcconfig
def test_suspicious_return_url(dummy_config, auth_request):
    with pytest.raises(DisallowedRedirect):
        init_view(auth_request, return_url="http://evil.com/steal-my-data")


@pytest.mark.parametrize(
    "get_kwargs",
    (
        {},
        {"return_url": ""},
        {"return_url": None},
    ),
)
@oidcconfig
def test_forgotten_return_url(dummy_config, auth_request, get_kwargs):
    with pytest.raises(ValueError):
        init_view(auth_request, **get_kwargs)


class IDPCheckInitView(OIDCAuthenticationRequestInitView):
    def check_idp_availability(self) -> None:
        raise OIDCProviderOutage("The internet is bwoken.")


oidc_init_with_idp_check = IDPCheckInitView.as_view(
    identifier="test-oidc", allow_next_from_query=True
)


@oidcconfig(check_op_availability=True)
def test_idp_check_mechanism(dummy_config, auth_request, settings):
    with pytest.raises(OIDCProviderOutage):
        oidc_init_with_idp_check(auth_request)
