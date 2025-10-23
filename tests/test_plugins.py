import logging

import pytest

from mozilla_django_oidc_db.registry import register as registry

from .conftest import oidcconfig
from .factories import UserFactory


@oidcconfig(
    enabled=True,
    extra_options={
        "user_settings.claim_mappings.username": ["username"],
        "user_settings.claim_mappings.first_name": [],
        "user_settings.claim_mappings.email": ["email"],
        "groups_settings.superuser_group_names": ["Superuser"],
        "groups_settings.claim_mapping": ["groups"],
    },
)
@pytest.mark.django_db
def test_update_user_from_claims(dummy_config):
    user = UserFactory.create(
        username="testuser",
        email="testuser@example.com",
        first_name="Test",
        is_superuser=False,
    )

    plugin = registry["test-oidc"]

    plugin.update_user(
        user,
        claims={
            "username": "testuser-MODIFIED",  # Username will not be modified
            "first_name": "Test-MODIFIED",  # First name claim path is not configured, so will not be updated
            "email": "testuser+MODIFIED@example.com",  # This should be updated
            "groups": ["Superuser"],
        },
    )

    user.refresh_from_db()

    assert user.username == "testuser"
    assert user.first_name == "Test"
    assert user.email == "testuser+MODIFIED@example.com"
    assert user.is_superuser


@oidcconfig(
    enabled=True,
    extra_options={
        "user_settings.claim_mappings.username": ["username"],
        "groups_settings.claim_mapping": ["not-present"],
    },
)
@pytest.mark.django_db
def test_no_groups_claim(dummy_config, caplog):
    user = UserFactory.create()

    plugin = registry["test-oidc"]

    with caplog.at_level(logging.DEBUG):
        plugin.update_user(
            user,
            claims={},
        )

    assert (
        "The configured groups claim 'not-present' was not found in the user info."
        in caplog.text
    )
