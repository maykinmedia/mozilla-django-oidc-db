import pytest
from django_setup_configuration.test_utils import build_step_config_from_sources

from mozilla_django_oidc_db.setup_configuration.steps import AdminOIDCConfigurationStep

"""
Key cloak credentials are setup for the keycloak docker-compose.yml.

`oidc_rp_client_id` and `oidc_rp_client_secret` are taken from the keycloak fixture
in /docker/import/test-reaml.json

See more info in /docker/README.md

"""


@pytest.fixture
def setup_config_discovery_model(settings):
    return build_step_config_from_sources(
        AdminOIDCConfigurationStep, "tests/setupconfig/files/discovery.yml"
    )


@pytest.fixture
def setup_config_defaults_model(settings):
    return build_step_config_from_sources(
        AdminOIDCConfigurationStep, "tests/setupconfig/files/defaults.yml"
    )


@pytest.fixture
def setup_config_full_model():
    return build_step_config_from_sources(
        AdminOIDCConfigurationStep, "tests/setupconfig/files/full_setup.yml"
    )
