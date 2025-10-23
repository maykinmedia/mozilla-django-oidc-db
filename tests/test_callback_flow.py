from typing import Protocol

from django.contrib.auth.models import User
from django.db import IntegrityError
from django.http import HttpRequest, HttpResponseRedirect
from django.test import Client
from django.urls import reverse
from django.utils.translation import gettext as _

import pytest
from pytest_django.asserts import assertContains, assertRedirects

from mozilla_django_oidc_db.models import (
    OIDCClient,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.typing import JSONObject
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestInitView
from testapp.backends import MockBackend

from .conftest import auth_request_mark as auth_request, oidcconfig
from .factories import UserFactory


class CallbackRequestMark(Protocol):
    def __call__(self, claims: JSONObject) -> pytest.MarkDecorator: ...


mock_backend_claims: CallbackRequestMark = pytest.mark.mock_backend_claims


@pytest.fixture
def mock_auth_backend(request, mocker):
    marker = request.node.get_closest_marker("mock_backend_claims")
    claims: JSONObject = marker.args[0] if marker else {"sub": "some_username"}
    mock_backend = MockBackend(claims=claims)
    backend_path = f"{MockBackend.__module__}.{MockBackend.__qualname__}"
    mocker.patch(
        "django.contrib.auth._get_backends", return_value=[(mock_backend, backend_path)]
    )
    return mock_backend


@pytest.fixture
def callback_client(callback_request: HttpRequest, client: Client) -> Client:
    session = client.session
    for key, value in callback_request.session.items():
        session[key] = value
    session.save()

    return client


@mock_backend_claims({"email": "collision@example.com", "sub": "some_username"})
@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
)
def test_duplicate_email_unique_constraint_violated(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
    mock_auth_backend: MockBackend,
    mocker,
):
    UserFactory.create(username="nonmatchingusername", email="collision@example.com")
    mocker.patch.object(
        mock_auth_backend,
        "create_user",
        side_effect=IntegrityError(
            """duplicate key value violates unique constraint "filled_email_unique"""
            """"\nDETAIL:  Key (email)=(collision@example.com) already exists.\n"""
        ),
    )
    callback_url = reverse("oidc_authentication_callback")
    error_url = reverse("admin-oidc-error")

    # check that the response redirects to the error page
    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assertRedirects(callback_response, error_url)

    # check that the error page displays error information
    error_page = callback_client.get(error_url)

    assert error_page.status_code == 200
    expected_error = (
        """duplicate key value violates unique constraint "filled_email_unique"""
        """"\nDETAIL:  Key (email)=(collision@example.com) already exists.\n"""
    )
    assert error_page.context["oidc_error"] == expected_error
    assertContains(error_page, "duplicate key value violates unique constraint")


@mock_backend_claims(
    {
        "sub": "some_username",
        "email": "collision@example.com",
        "wrong_is_superuser_value_type": "",  # should be boolean instead of string
    }
)
@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.is_superuser": ["wrong_is_superuser_value_type"]
    },
)
def test_validation_error_during_authentication(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
    mock_auth_backend: MockBackend,
):
    UserFactory.create(username="some_username", email="admin@example.com")
    callback_url = reverse("oidc_authentication_callback")
    error_url = reverse("admin-oidc-error")

    # check that the response redirects to the error page
    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assertRedirects(callback_response, error_url)

    # check that the error page displays error information
    error_page = callback_client.get(error_url)

    assert error_page.status_code == 200
    expected_error = _("“%(value)s” value must be either True or False.") % {
        "value": ""
    }
    assert error_page.context["oidc_error"] == expected_error
    assertContains(error_page, expected_error)


@mock_backend_claims(
    {
        "email": "nocollision@example.com",
        "sub": "some_username",
    }
)
@auth_request(next="/admin/")
@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
)
def test_happy_flow(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
    mock_auth_backend: MockBackend,
):
    callback_url = reverse("oidc_authentication_callback")

    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assertRedirects(callback_response, "/admin/", fetch_redirect_response=False)
    user = User.objects.get(email="nocollision@example.com")
    assert user.username == "some_username"


@mock_backend_claims({})
@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
)
def test_empty_claims_returned(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
    mock_auth_backend: MockBackend,
):
    """
    Assert that the login procedure fails gracefully when no user claims are returned.
    """
    callback_url = reverse("oidc_authentication_callback")
    error_url = reverse("admin-oidc-error")

    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assertRedirects(callback_response, error_url, fetch_redirect_response=False)
    assert not User.objects.exists()


def test_tampering_with_parameters_invalid_state(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
):
    callback_url = reverse("oidc_authentication_callback")
    valid_state_key = callback_request.GET["state"]
    assert valid_state_key != "invalid-state"

    callback_response = callback_client.get(callback_url, {"state": "invalid-state"})

    assert callback_response.status_code == 400


def test_invalid_reference_to_config_identifier(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
):
    # This only guards against programmer mistakes downstream that would lead to the
    # end-user being able to manipulate the config_identifier being set in the state. It is
    # a synthetic case.
    callback_url = reverse("oidc_authentication_callback")
    state_key = callback_request.GET["state"]
    session = callback_client.session
    del session["oidc_states"][state_key]["config_identifier"]
    session.save()

    callback_response = callback_client.get(callback_url, {"state": state_key})

    assert callback_response.status_code == 400


@pytest.mark.django_db
@oidcconfig(enabled=False, oidc_op_authorization_endpoint="bad")
def test_wrong_config_model_used(
    dummy_config: OIDCClient,
    auth_request: HttpRequest,
    client: Client,
):
    init_view = OIDCAuthenticationRequestInitView.as_view(identifier="test-oidc")
    init_view(auth_request)
    # there is only one state expected
    state_key = list(auth_request.session["oidc_states"].keys())[0]
    callback_url = reverse("oidc_authentication_callback")
    session = client.session
    for key in auth_request.session.keys():
        session[key] = auth_request.session[key]
    session.save()

    callback_response = client.get(
        callback_url, {"state": state_key, "code": "irrelevant"}
    )

    assert callback_response.status_code == 302
    assert isinstance(callback_response, HttpResponseRedirect)
    assert callback_response.url == "/admin/login/failure/"


@auth_request(next="/admin/")
@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
)
def test_error_first_cleared_after_succesful_login(
    dummy_config: OIDCClient,
    callback_request: HttpRequest,
    callback_client: Client,
    mock_auth_backend: MockBackend,
):
    session = callback_client.session
    session["oidc-error"] = "some error"
    session.save()
    callback_url = reverse("oidc_authentication_callback")
    error_url = reverse("admin-oidc-error")

    # check that error page works
    error_response = callback_client.get(error_url)
    assert error_response.status_code == 200

    # now on succesfull login, the error must be cleared
    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assertRedirects(callback_response, "/admin/", fetch_redirect_response=False)

    error_response = callback_client.get(error_url)
    assert error_response.status_code == 403
