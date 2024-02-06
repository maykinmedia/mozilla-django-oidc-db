from typing import Iterator

import pytest

from mozilla_django_oidc_db.forms import OpenIDConnectConfigForm
from mozilla_django_oidc_db.models import OpenIDConnectConfig, get_default_scopes

KEYCLOAK_BASE_URL = "http://localhost:8080/realms/test/"


@pytest.fixture
def mock_state_and_nonce(mocker):
    mocker.patch(
        "mozilla_django_oidc.views.get_random_string",
        return_value="not-a-random-string",
    )


@pytest.fixture
def keycloak_config(db) -> Iterator[OpenIDConnectConfig]:
    """
    Keycloak configuration for the provided docker-compose.yml setup.

    This install a configuration (solo model) configured with the appropriate
    credentials.

    When not using VCR cassettes, make sure the service is up and running:

    .. code-block:: console

        docker-compose up -d

    """
    endpoints = OpenIDConnectConfigForm.get_endpoints_from_discovery(KEYCLOAK_BASE_URL)

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
        },
    )
    # in case caching is setup, ensure that it is invalidated
    config.save()

    yield config

    OpenIDConnectConfig.clear_cache()
