from json.decoder import JSONDecodeError
from unittest.mock import patch

from django.test import Client
from django.urls import reverse
from django.utils.translation import gettext as _

import pytest
import requests_mock
from requests.exceptions import RequestException

from mozilla_django_oidc_db.forms import OIDCProviderForm
from mozilla_django_oidc_db.models import OIDCClient
from tests.factories import UserFactory


@pytest.mark.django_db
def test_derive_endpoints_success():
    form_data = {
        "identifier": "test-tralala",
        "oidc_op_discovery_endpoint": "http://discovery-endpoint.nl/",
    }
    form = OIDCProviderForm(data=form_data)

    configuration = {
        "authorization_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/auth",
        "token_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/token",
        "userinfo_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/userinfo",
        "jwks_uri": "http://provider.com/auth/realms/master/protocol/openid-connect/certs",
        "end_session_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/logout",
    }
    with requests_mock.Mocker() as m:
        m.get(
            "http://discovery-endpoint.nl/.well-known/openid-configuration",
            json=configuration,
        )
        assert form.is_valid()

    config = form.save()
    assert (
        config.oidc_op_authorization_endpoint
        == "http://provider.com/auth/realms/master/protocol/openid-connect/auth"
    )
    assert (
        config.oidc_op_token_endpoint
        == "http://provider.com/auth/realms/master/protocol/openid-connect/token"
    )
    assert (
        config.oidc_op_user_endpoint
        == "http://provider.com/auth/realms/master/protocol/openid-connect/userinfo"
    )
    assert (
        config.oidc_op_jwks_endpoint
        == "http://provider.com/auth/realms/master/protocol/openid-connect/certs"
    )


@pytest.mark.django_db
def test_derive_endpoints_extra_field():
    form_data = {
        "identifier": "test-tralala",
        "oidc_op_discovery_endpoint": "http://discovery-endpoint.nl/",
    }

    class ExtendedOIDCProviderForm(OIDCProviderForm):
        required_endpoints = OIDCProviderForm.required_endpoints
        # Define an extra field to derive from the configuration
        oidc_mapping = dict(
            **OIDCProviderForm.oidc_mapping,
            **{"logout_endpoint": "end_session_endpoint"},
        )

    form = ExtendedOIDCProviderForm(data=form_data)

    configuration = {
        "authorization_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/auth",
        "token_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/token",
        "userinfo_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/userinfo",
        "jwks_uri": "http://provider.com/auth/realms/master/protocol/openid-connect/certs",
        "end_session_endpoint": "http://provider.com/auth/realms/master/protocol/openid-connect/logout",
    }
    with requests_mock.Mocker() as m:
        m.get(
            "http://discovery-endpoint.nl/.well-known/openid-configuration",
            json=configuration,
        )
        assert form.is_valid()

    # The endpoint that was added to the mapping on the extended form
    # should be present in the cleaned data
    assert (
        form.cleaned_data["logout_endpoint"]
        == "http://provider.com/auth/realms/master/protocol/openid-connect/logout"
    )


@patch("requests.get", side_effect=RequestException)
@pytest.mark.django_db  # Validation that the identifier is unique uses the DB
def test_derive_endpoints_request_error(*m):
    form_data = {
        "identifier": "test-tralala",
        "oidc_op_discovery_endpoint": "http://discovery-endpoint.nl",
    }
    form = OIDCProviderForm(data=form_data)

    form.is_valid()

    assert form.errors == {
        "oidc_op_discovery_endpoint": [
            _("Something went wrong while retrieving the configuration.")
        ]
    }


@patch("requests.get", side_effect=JSONDecodeError("error", "test", 1))
@pytest.mark.django_db
def test_derive_endpoints_json_error(*m):
    form_data = {
        "identifier": "test-tralala",
        "oidc_op_discovery_endpoint": "http://discovery-endpoint.nl",
    }
    form = OIDCProviderForm(data=form_data)

    form.is_valid()

    assert form.errors == {
        "oidc_op_discovery_endpoint": [
            _("Something went wrong while retrieving the configuration.")
        ]
    }


@pytest.mark.vcr
def test_derive_endpoints_google_oidc():
    endpoints = OIDCProviderForm.get_endpoints_from_discovery(
        base_url="https://accounts.google.com"
    )

    assert endpoints == {
        "oidc_op_authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "oidc_op_token_endpoint": "https://oauth2.googleapis.com/token",
        "oidc_op_user_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "oidc_op_jwks_endpoint": "https://www.googleapis.com/oauth2/v3/certs",
    }


@pytest.mark.django_db
def test_no_discovery_endpoint_other_fields_required():
    form_data = {
        "identifier": "test-tralala",
    }
    form = OIDCProviderForm(data=form_data)

    form.is_valid()

    assert form.errors == {
        "oidc_op_authorization_endpoint": [_("This field is required.")],
        "oidc_op_token_endpoint": [_("This field is required.")],
        "oidc_op_user_endpoint": [_("This field is required.")],
    }


def test_admin_form_readonly_access():
    # Empty the base_fields, causing OIDCProviderForm.fields to be empty
    # as well, which is also the case for when users access the form with
    # read only access
    OIDCProviderForm.base_fields = {}

    # Form initialization should not raise any errors
    OIDCProviderForm()


@pytest.mark.django_db
def test_get_custom_options_schema(client: Client):
    config = OIDCClient.objects.get(identifier="test-oidc")
    user = UserFactory.create(is_superuser=True, is_staff=True)
    client.force_login(user)

    response = client.get(
        reverse(
            "admin:mozilla_django_oidc_db_oidcclient_change",
            kwargs={"object_id": config.pk},
        ),
    )

    assert response.status_code == 200
    assert b"custom-option-key" in response.content
