"""
Test the init flow through a custom view and config.
"""

from urllib.parse import parse_qs, urlsplit

from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import DisallowedRedirect
from django.test import RequestFactory

import pytest

from mozilla_django_oidc_db.exceptions import OIDCProviderOutage
from mozilla_django_oidc_db.models import OpenIDConnectConfig
from mozilla_django_oidc_db.views import OIDCInit

pytestmark = [pytest.mark.django_db]


@pytest.fixture
def auth_request(rf: RequestFactory):
    request = rf.get("/some-auth", {"next": "/ignored"})
    session = SessionStore()
    session.save()
    request.session = session
    return request


# Use a proxy model to modify behaviour without needing migrations/models machinery.


class static_setting:
    def __init__(self, val):
        self.val = val

    def __get__(self, obj, objtype):
        return self.val

    def __set__(self, obj, val):
        pass


class CustomConfig(OpenIDConnectConfig):
    class Meta:
        proxy = True
        app_label = "mozilla_django_oidc_db"

    enabled = static_setting(True)
    oidc_rp_client_id = static_setting("fixed_client_id")
    oidc_rp_client_secret = static_setting("supersecret")
    oidc_op_authorization_endpoint = static_setting("https://example.com/oidc/auth")


oidc_init = OIDCInit.as_view(config_class=CustomConfig)


def test_redirects_to_oidc_provider(auth_request):
    response = oidc_init(auth_request, return_url="/fixed-next")

    assert response.status_code == 302
    parsed_url = urlsplit(response.url)
    assert parsed_url.scheme == "https"
    assert parsed_url.netloc == "example.com"
    assert parsed_url.path == "/oidc/auth"

    # introspect state
    state_key = parse_qs(parsed_url.query)["state"][0]
    state = auth_request.session["oidc_states"][state_key]
    assert state["config_class"] == "mozilla_django_oidc_db.CustomConfig"
    # upstream library
    assert auth_request.session["oidc_login_next"] == "/fixed-next"
    # our own addition
    assert auth_request.session["oidc-db_redirect_next"] == "/fixed-next"


def test_suspicious_return_url(auth_request):
    with pytest.raises(DisallowedRedirect):
        oidc_init(auth_request, return_url="http://evil.com/steal-my-data")


@pytest.mark.parametrize(
    "get_kwargs",
    (
        {},
        {"return_url": ""},
        {"return_url": None},
    ),
)
def test_forgotten_return_url(auth_request, get_kwargs):
    with pytest.raises(ValueError):
        oidc_init(auth_request, **get_kwargs)


class IDPCheckInitView(OIDCInit):
    def check_idp_availability(self) -> None:
        raise OIDCProviderOutage("The internet is bwoken.")


oidc_init_with_idp_check = IDPCheckInitView.as_view(
    config_class=CustomConfig, allow_next_from_query=True
)


def test_idp_check_mechanism(auth_request):
    with pytest.raises(OIDCProviderOutage):
        oidc_init_with_idp_check(auth_request)
