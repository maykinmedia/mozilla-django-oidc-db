from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterator
from urllib.parse import parse_qs, urlsplit

from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest
from django.test import RequestFactory

import pytest

if TYPE_CHECKING:
    from mozilla_django_oidc_db.models import OpenIDConnectConfig

KEYCLOAK_BASE_URL = "http://localhost:8080/realms/test/"


@pytest.fixture
def mock_state_and_nonce(mocker):
    mocker.patch(
        "mozilla_django_oidc.views.get_random_string",
        return_value="not-a-random-string",
    )
    mocker.patch(
        "mozilla_django_oidc.middleware.get_random_string",
        return_value="not-a-random-string",
    )


@pytest.fixture
def dummy_config(request, db) -> Iterator[OpenIDConnectConfig]:
    """
    OIDC Provider configuration for a fictious provider.

    The URLs here are made up. Use this fixture when the actual provider authentication
    aspect is irrelevant.
    """
    # local imports to so that `pytest --help` can load this file
    from mozilla_django_oidc_db.models import OpenIDConnectConfig

    marker = request.node.get_closest_marker("oidcconfig")
    overrides: dict[str, Any] = marker.kwargs if marker else {}
    BASE = "https://mock-oidc-provider:9999"

    config, _ = OpenIDConnectConfig.objects.update_or_create(
        pk=OpenIDConnectConfig.singleton_instance_id,
        defaults={
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
            "sync_groups": False,
            **overrides,
        },
    )
    # in case caching is setup, ensure that it is invalidated
    config.save()

    yield config

    OpenIDConnectConfig.clear_cache()


@pytest.fixture
def keycloak_config(request, db) -> Iterator[OpenIDConnectConfig]:
    """
    Keycloak configuration for the provided docker-compose.yml setup.

    This install a configuration (solo model) configured with the appropriate
    credentials.

    When not using VCR cassettes, make sure the service is up and running:

    .. code-block:: console

        docker-compose up -d

    """
    # local imports to so that `pytest --help` can load this file
    from mozilla_django_oidc_db.forms import OpenIDConnectConfigForm
    from mozilla_django_oidc_db.models import OpenIDConnectConfig, get_default_scopes

    endpoints = OpenIDConnectConfigForm.get_endpoints_from_discovery(KEYCLOAK_BASE_URL)

    marker = request.node.get_closest_marker("oidcconfig")
    overrides: dict[str, Any] = marker.kwargs if marker else {}

    config, _ = OpenIDConnectConfig.objects.update_or_create(
        pk=OpenIDConnectConfig.singleton_instance_id,
        defaults={
            "enabled": True,
            "oidc_rp_client_id": "testid",
            "oidc_rp_client_secret": "7DB3KUAAizYCcmZufpHRVOcD0TOkNO3I",
            "oidc_rp_sign_algo": "RS256",
            **endpoints,
            "oidc_rp_scopes_list": get_default_scopes() + ["bsn", "kvk"],
            "sync_groups": False,
            **overrides,
        },
    )
    # in case caching is setup, ensure that it is invalidated
    config.save()

    yield config

    OpenIDConnectConfig.clear_cache()


@pytest.fixture
def auth_request(request, rf: RequestFactory):
    """
    A django request for the OIDC auth request flow.
    """
    marker = request.node.get_closest_marker("auth_request")
    next_url = marker.kwargs.get("next") if marker else None
    if next_url is None:
        next_url = "/ignored"

    request = rf.get("/some-auth", {"next": next_url})
    session = SessionStore()
    session.save()
    request.session = session
    return request


@pytest.fixture
def callback_request(
    request, auth_request: HttpRequest, rf: RequestFactory
) -> HttpRequest:
    """
    A django request primed by an OIDC auth request flow, ready for the callback flow.
    """
    from mozilla_django_oidc_db.config import store_config
    from mozilla_django_oidc_db.views import OIDCAuthenticationRequestView

    # set a default in case no marker is provided
    init_view = OIDCAuthenticationRequestView.as_view()

    marker = request.node.get_closest_marker("callback_request")
    if marker and (_init_view := marker.kwargs.get("init_view")):
        init_view = _init_view

    response = init_view(auth_request)
    redirect_url: str = response.url  # type: ignore
    assert redirect_url
    state_key = parse_qs(urlsplit(redirect_url).query)["state"][0]

    callback_request = rf.get(
        "/oidc/dummy-callback",
        {"state": state_key, "code": "dummy-oidc-code"},
    )
    callback_request.session = auth_request.session
    store_config(callback_request)
    return callback_request
