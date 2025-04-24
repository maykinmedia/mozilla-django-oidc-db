from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterator
from urllib.parse import parse_qs, urlsplit

from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest
from django.test import RequestFactory

import pytest

from tests.utils import create_or_update_configuration

if TYPE_CHECKING:
    from mozilla_django_oidc_db.models import OIDCConfig

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
def disabled_config(request, db) -> Iterator[OIDCConfig]:
    """
    OIDC configuration with enabled=False.

    Use this fixture when you need a configuration that is currently disabled.
    """
    from mozilla_django_oidc_db.models import OIDCConfig, OIDCProviderConfig

    BASE = "https://mock-oidc-provider:9999"

    oidc_provider_config, _ = OIDCProviderConfig.objects.update_or_create(
        identifier="test-oidc-provider",
        defaults={
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
        },
    )

    config, _ = OIDCConfig.objects.update_or_create(
        identifier="test-oidc-disabled",
        defaults={
            "enabled": False,
            "oidc_provider_config": oidc_provider_config,
        },
    )

    yield config


@pytest.fixture
def dummy_config(request, db) -> Iterator[OIDCConfig]:
    """
    OIDC configuration for a fictious provider.

    The URLs here are made up. Use this fixture when the actual provider authentication
    aspect is irrelevant.
    """
    marker = request.node.get_closest_marker("oidcconfig")
    overrides: dict[str, Any] = marker.kwargs if marker else {}
    BASE = "https://mock-oidc-provider:9999"

    fields = {
        # Provider config
        "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
        "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
        "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
        "oidc_op_token_endpoint": f"{BASE}/oidc/token",
        "oidc_op_user_endpoint": f"{BASE}/oidc/user",
        # Config
        "enabled": True,
        "oidc_rp_client_id": "fake",
        "oidc_rp_client_secret": "even-faker",
        "oidc_rp_sign_algo": "RS256",
        "options": {
            "user_settings": {
                "claim_mappings": {
                    "username": ["sub"],
                    "email": ["email"],
                }
            },
            "groups_settings": {"make_users_staff": True, "sync": False},
        },
        **overrides,
    }

    config = create_or_update_configuration("test-oidc-provider", "test-oidc", fields)

    yield config


@pytest.fixture
def keycloak_config(request, db) -> Iterator[OIDCConfig]:
    """
    Keycloak configuration for the provided docker-compose.yml setup.

    This install a configuration (solo model) configured with the appropriate
    credentials.

    When not using VCR cassettes, make sure the service is up and running:

    .. code-block:: console

        docker-compose up -d

    """
    # local imports to so that `pytest --help` can load this file
    from mozilla_django_oidc_db.forms import OIDCProviderConfigForm
    from mozilla_django_oidc_db.models import get_default_scopes

    endpoints = OIDCProviderConfigForm.get_endpoints_from_discovery(KEYCLOAK_BASE_URL)

    marker = request.node.get_closest_marker("oidcconfig")
    overrides: dict[str, Any] = marker.kwargs if marker else {}

    fields = {
        **endpoints,
        "enabled": True,
        "oidc_rp_client_id": "testid",
        "oidc_rp_client_secret": "7DB3KUAAizYCcmZufpHRVOcD0TOkNO3I",
        "oidc_rp_sign_algo": "RS256",
        **endpoints,
        "oidc_rp_scopes_list": get_default_scopes() + ["bsn", "kvk"],
        "sync_groups": False,
        "options": {
            "user_settings": {
                "claim_mappings": {
                    "username": ["sub"],
                    "email": ["email"],
                }
            },
            "groups_settings": {"make_users_staff": True, "sync": False},
        },
        **overrides,
    }
    config = create_or_update_configuration(
        "test-provider-keycloak", "test-keycloak", fields
    )
    config = create_or_update_configuration(
        "test-provider-keycloak", "test-keycloak-custom", fields
    )

    yield config


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
    from mozilla_django_oidc_db.views import OIDCAuthenticationRequestInitView

    # set a default in case no marker is provided
    init_view = OIDCAuthenticationRequestInitView.as_view(identifier="test-oidc")

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
