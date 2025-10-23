import logging

from django.contrib.auth.models import Group, User
from django.contrib.sessions.backends.base import SessionBase
from django.core.exceptions import BadRequest, ImproperlyConfigured
from django.http import HttpRequest
from django.test import RequestFactory

import pytest
from mozilla_django_oidc.auth import OIDCAuthenticationBackend as UpstreamBackend

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.models import (
    OIDCClient,
    OIDCProvider,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestInitView
from testapp.backends import MockBackend

from .conftest import callback_request_mark as callback_request, oidcconfig

#
# DYNAMIC CONFIGURATION TESTS
#


@oidcconfig(enabled=False)
def test_authenticate_oidc_not_enabled(dummy_config, callback_request: HttpRequest):
    backend = OIDCAuthenticationBackend()

    user = backend.authenticate(callback_request)

    # Authentication with the backend should not return a result,
    # because OIDC is not enabled
    assert user is None


@pytest.mark.django_db
@oidcconfig
@callback_request(
    init_view=OIDCAuthenticationRequestInitView.as_view(identifier="test-oidc-disabled")
)
def test_authentication_loads_config_from_init_state(
    dummy_config, disabled_config, callback_request: HttpRequest
):
    assert dummy_config.enabled is True
    backend = OIDCAuthenticationBackend()
    # check that we correctly initialized our OIDC state
    state_key = callback_request.GET["state"]
    state = callback_request.session["oidc_states"][state_key]
    assert state["config_identifier"] == "test-oidc-disabled"

    user = backend.authenticate(callback_request)

    # Authentication with the backend should not return a result,
    # because OIDC is not enabled
    assert user is None


@pytest.mark.parametrize("sign_alg", ("RS**", "ES**"))
@pytest.mark.django_db
def test_settings_still_validated(settings, sign_alg: str):
    """
    Test that the upstream library settings checks are still performed.
    """
    config = OIDCClient.objects.get(identifier="test-oidc-not-configured")
    oidc_provider = OIDCProvider.objects.create(
        identifier="test-not-configured-provider", oidc_op_jwks_endpoint=""
    )
    config.oidc_rp_sign_algo = sign_alg
    config.oidc_rp_idp_sign_key = ""
    config.oidc_provider = oidc_provider
    config.save()
    backend = OIDCAuthenticationBackend()
    backend.config = config

    with pytest.raises(ImproperlyConfigured):
        # the exact setting doesn't matter
        backend.OIDC_RP_CLIENT_ID  # noqa: B018

    # check that the same error is raised by the upstream backend
    settings.OIDC_RP_SIGN_ALGO = sign_alg
    settings.OIDC_RP_IDP_SIGN_KEY = None
    settings.OIDC_OP_JWKS_ENDPOINT = None
    with pytest.raises(ImproperlyConfigured):
        UpstreamBackend()


#
# LOGGING AND OBFUSCATION TESTS
#


@oidcconfig(
    enabled=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.sensitive_claims": [
            ["sensitive_claim1"],
            ["parent", "sensitive_claim2"],
        ],
    },
)
def test_obfuscates_sensitive_claims(dummy_config, caplog):
    caplog.set_level(logging.DEBUG, logger="mozilla_django_oidc_db.plugins")
    backend = OIDCAuthenticationBackend()
    backend.config = dummy_config

    claims_ok = backend.verify_claims(
        {
            "sub": "some-unique-id",
            "sensitive_claim1": "obfuscate-me!",
            "parent": {
                "sensitive_claim2": "obfuscate-me!",
                "other": "not-sensitive",
            },
        }
    )

    assert claims_ok

    # check that the emitted log records have the sensitive claims obfuscated
    log_message: str = next(
        message
        for rec in caplog.records
        if (message := rec.message).startswith("OIDC claims received")
    )

    assert "some-unique-id" not in log_message
    assert "obfuscate-me!" not in log_message
    assert "not-sensitive" in log_message


#
# USER CREATION & UPDATING TESTS
#


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.first_name": ["given_name"],
        "user_settings.claim_mappings.last_name": ["family_name"],
    },
)
def test_create_user_with_default_config(dummy_config, callback_request: HttpRequest):
    assert not User.objects.exists()
    backend = MockBackend(
        claims={
            "sub": "123456",
            "email": "admin@localhost",
            "given_name": "John",
            "family_name": "Doe",
        }
    )

    user = backend.authenticate(request=callback_request)

    assert user is not None
    assert isinstance(user, User)

    # Verify that a user is created with the correct values
    assert user.pk is not None
    assert user.username == "123456"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.first_name": ["given_name"],
        "user_settings.claim_mappings.last_name": ["family_name"],
        "user_settings.username_case_sensitive": False,
    },
)
def test_case_insensitive_username_lookups(
    settings, dummy_config, callback_request: HttpRequest
):
    existing_user = User.objects.create(username="ADMIN")

    backend = MockBackend(
        claims={
            "sub": "admin",
            "email": "admin@localhost",
            "given_name": "John",
            "family_name": "Doe",
        }
    )

    user = backend.authenticate(request=callback_request)

    assert user == existing_user
    assert User.objects.count() == 1


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["user", "username"],
        "user_settings.claim_mappings.first_name": ["profile", "given_name"],
        "user_settings.claim_mappings.last_name": ["profile", "family_name"],
        "user_settings.claim_mappings.email": ["attributes.email"],
        "groups_settings.claim_mapping": ["user", "groups.names"],
    },
)
def test_create_user_with_custom_and_complex_config(
    dummy_config, callback_request: HttpRequest
):
    assert not User.objects.exists()
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "user": {
                "username": "admin",
                "groups.names": ["supergroup"],
            },
            "profile": {
                "given_name": "John",
                "family_name": "Doe",
            },
            "attributes.email": "admin@localhost",
        }
    )

    user = backend.authenticate(request=callback_request)

    assert user is not None
    assert isinstance(user, User)

    # Verify that a user is created with the correct values
    assert user.pk is not None
    assert user.username == "admin"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["user", "username"],
        "groups_settings.claim_mapping": ["user", "groups.names"],
        "groups_settings.sync": True,
    },
)
def test_create_user_with_mapped_groups(dummy_config, callback_request: HttpRequest):
    assert not User.objects.exists()
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "user": {
                "username": "admin",
                "groups.names": ["supergroup"],
            },
            "email": "admin@localhost",
            "given_name": "John",
            "family_name": "Doe",
        }
    )

    user = backend.authenticate(request=callback_request)

    assert user is not None
    assert isinstance(user, User)

    group_names = set(user.groups.values_list("name", flat=True))
    assert group_names == {"supergroup"}


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": True,
    },
)
def test_groups_claim_string_instead_of_list(
    dummy_config, callback_request: HttpRequest
):
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "admin",
            "email": "admin@localhost",
            "given_name": "John",
            "family_name": "Doe",
            "roles": "admins",
        }
    )

    user = backend.authenticate(request=callback_request)

    assert user is not None
    assert isinstance(user, User)

    assert set(user.groups.values_list("name", flat=True)) == {"admins"}


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["user", "username"],
        "user_settings.claim_mappings.email": ["attributes.email"],
        "user_settings.claim_mappings.first_name": ["profile", "given_name"],
        "user_settings.claim_mappings.last_name": ["profile", "family_name"],
        "groups_settings.claim_mapping": ["user", "groups.names"],
        "groups_settings.sync": True,
        "groups_settings.sync_pattern": "*",
        "groups_settings.default_groups": [],  # explicitly clear to wipe any possible implicit defaults
    },
)
def test_update_user_with_custom_and_complex_config(
    dummy_config, callback_request: HttpRequest
):
    existing_user = User.objects.create(
        username="admin",
        email="outdated@example.com",
        first_name="O.",
        last_name="Utdated",
        is_superuser=True,
    )
    group = Group.objects.create(name="to-remove")
    existing_user.groups.add(group)

    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "user": {
                "username": "admin",
                "groups.names": ["supergroup"],
            },
            "profile": {
                "given_name": "John",
                "family_name": "Doe",
            },
            "attributes.email": "admin@localhost",
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)

    # check that the existing user was correctly found based on the username claim
    assert user == existing_user

    # Verify that a user is created with the correct values
    assert user.username == "admin"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    # is_superuser may not be affected if `superuser_group_names` is not set
    assert user.is_superuser

    # missing groups must be created because of sync_groups and sync_groups_glob_pattern
    assert set(user.groups.values_list("name", flat=True)) == {"supergroup"}


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "groups_settings.claim_mapping": [],
        "groups_settings.sync": True,
        "groups_settings.sync_pattern": "*",
    },
)
def test_authenticate_user_no_group_sync_without_claim(
    dummy_config, callback_request: HttpRequest
):
    Group.objects.create(name="group1")
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "roles": ["group1", "newgroup"],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    # Verify that no groups were created or assigned
    assert Group.objects.count() == 1
    assert not user.groups.exists()


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": True,
        "groups_settings.sync_pattern": "myapp:*",
    },
)
def test_authenticate_user_groups_glob_pattern(
    dummy_config, callback_request: HttpRequest
):
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "roles": ["admin", "myapp:editor"],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    # Verify that no groups were created or assigned
    assert Group.objects.count() == 1
    assert set(user.groups.values_list("name", flat=True)) == {"myapp:editor"}


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": True,
        "groups_settings.sync_pattern": "myapp:*",
        "groups_settings.default_groups": ["default1"],
    },
)
def test_authenticate_user_groups_and_default_groups(
    dummy_config, callback_request: HttpRequest
):
    Group.objects.create(name="default1")
    Group.objects.create(name="default2")
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "roles": ["admin", "myapp:editor"],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    # Verify that no groups were created or assigned
    assert Group.objects.count() == 3
    assert set(user.groups.values_list("name", flat=True)) == {
        "myapp:editor",
        "default1",
    }


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.is_superuser": ["is_god"],
        "groups_settings.make_users_staff": True,
    },
)
def test_authenticate_user_make_staff(dummy_config, callback_request: HttpRequest):
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "is_god": 1,
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    assert user.is_staff
    assert user.is_superuser


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "groups_settings.make_users_staff": True,
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": False,
        "groups_settings.superuser_group_names": ["superuser"],
    },
)
def test_authenticate_user_make_superuser_based_on_group(
    dummy_config, callback_request: HttpRequest
):
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "roles": ["superuser", "groupadmin"],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    assert user.is_superuser
    assert not Group.objects.exists()


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "groups_settings.make_users_staff": True,
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": False,
        "groups_settings.superuser_group_names": ["superuser"],
    },
)
def test_remove_superuser_based_on_group(dummy_config, callback_request: HttpRequest):
    existing_user = User.objects.create_user(username="123456", is_superuser=True)
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "roles": ["nosuperuser", "groupadmin"],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    assert user == existing_user
    assert not user.is_superuser


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "groups_settings.make_users_staff": True,
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": False,
        "groups_settings.superuser_group_names": [],
    },
)
def test_do_nothing_if_no_superuser_groups_configured(
    dummy_config, callback_request: HttpRequest
):
    existing_user = User.objects.create_user(username="123456", is_superuser=True)
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "123456",
            "roles": ["nosuperuser", "groupadmin"],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert isinstance(user, User)
    assert user == existing_user
    assert user.is_superuser


#
# AUTHENTICATE FLOW PROBLEMS
#


@oidcconfig(enabled=True)
def test_authenticate_called_without_args(dummy_config):
    backend = OIDCAuthenticationBackend()

    user = backend.authenticate(request=None)

    assert user is None


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
    },
)
def test_username_claim_empty(dummy_config, callback_request: HttpRequest):
    backend = MockBackend(claims={"sub": ""})

    user = backend.authenticate(request=callback_request)

    assert user is None


@oidcconfig(enabled=True, userinfo_claims_source=UserInformationClaimsSources.id_token)
def test_empty_claims(dummy_config, callback_request: HttpRequest):
    backend = MockBackend(claims={})

    user = backend.authenticate(request=callback_request)

    assert user is None


@oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "groups_settings.claim_mapping": ["roles"],
        "groups_settings.sync": True,
    },
)
def test_groups_claim_wrong_type(dummy_config, callback_request: HttpRequest):
    backend = MockBackend(
        # a variation of nested paths, custom claims and dots in claim names
        claims={
            "sub": "admin",
            "email": "admin@localhost",
            "given_name": "John",
            "family_name": "Doe",
            "roles": ["group1", None, 123],
        }
    )

    user = backend.authenticate(request=callback_request)

    assert user is not None
    assert isinstance(user, User)

    # fails silently
    assert not user.groups.exists()


def test_authenticate_without_previous_state(rf: RequestFactory):
    request = rf.get("/oidc/callback", {"state": "foo", "code": "bar"})
    request.session = SessionBase()
    backend = OIDCAuthenticationBackend()

    with pytest.raises(BadRequest):
        backend.authenticate(request=request)


#
# CACHE/QUERYING FOR CONFIG DURING PERMISSON CHECK.
#


def test_init_does_not_perform_config_io(mocker):
    """
    Regression test for https://github.com/maykinmedia/mozilla-django-oidc-db/issues/30

    This test will fail if IO is performed in one of two ways:

    * assertion fails because get_setting_from_config was called
    * pytest will complain about database access which is forbidden because there is
      no pytest.mark.django_db present (deliberately)
    """
    m_get_setting = mocker.patch(
        "mozilla_django_oidc_db.config.get_setting_from_config"
    )

    # instantiate
    OIDCAuthenticationBackend()

    m_get_setting.assert_not_called()
