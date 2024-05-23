import logging

from django.contrib.auth.models import Group, User
from django.core.exceptions import BadRequest, ImproperlyConfigured
from django.http import HttpRequest
from django.test import RequestFactory

import pytest
from mozilla_django_oidc.auth import OIDCAuthenticationBackend as UpstreamBackend

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.config import lookup_config
from mozilla_django_oidc_db.models import (
    OpenIDConnectConfig,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.views import OIDCAuthenticationRequestView
from testapp.backends import MockBackend
from testapp.models import EmptyConfig

from .custom_config import oidc_init_disabled

#
# DYNAMIC CONFIGURATION TESTS
#


@pytest.mark.oidcconfig(enabled=False)
def test_authenticate_oidc_not_enabled(dummy_config, callback_request: HttpRequest):
    backend = OIDCAuthenticationBackend()

    user = backend.authenticate(callback_request)

    # Authentication with the backend should not return a result,
    # because OIDC is not enabled
    assert user is None


@pytest.mark.callback_request(init_view=oidc_init_disabled)
def test_authentication_loads_config_from_init_state(
    dummy_config, callback_request: HttpRequest
):
    assert dummy_config.enabled is True
    backend = OIDCAuthenticationBackend()
    # check that we correctly initialized our OIDC state
    state_key = callback_request.GET["state"]
    state = callback_request.session["oidc_states"][state_key]
    assert state["config_class"] == "mozilla_django_oidc_db.DisabledConfig"

    user = backend.authenticate(callback_request)

    # Authentication with the backend should not return a result,
    # because OIDC is not enabled
    assert user is None


@pytest.mark.parametrize(
    "setting,expected",
    (
        ("OIDCDB_USERNAME_CASE_SENSITIVE", False),
        ("OIDCDB_CLAIM_MAPPING", {"foo": "bar"}),
        ("OIDCDB_GROUPS_CLAIM", ["roles"]),
        ("OIDCDB_DEFAULT_GROUPS", ["one", "two"]),
        ("OIDCDB_SYNC_MISSING_GROUPS", False),
        ("OIDCDB_SYNC_GROUPS_GLOB_PATTERN", "in:*:tricate"),
        ("OIDCDB_MAKE_USERS_STAFF", True),
        ("OIDCDB_SUPERUSER_GROUP_NAMES", ["we are gods", "bow for us"]),
    ),
)
@pytest.mark.django_db
def test_grabs_config_from_django_settings_if_missing_on_model(
    settings, setting, expected
):
    setattr(settings, setting, expected)
    backend = OIDCAuthenticationBackend()
    backend.config_class = EmptyConfig

    value = getattr(backend, setting)

    assert value == expected


@pytest.mark.parametrize("sign_alg", ("RS**", "ES**"))
@pytest.mark.oidcconfig()
def test_settings_still_validated(dummy_config, settings, sign_alg: str):
    """
    Test that the upstream library settings checks are still performed.
    """
    dummy_config.oidc_rp_sign_algo = sign_alg
    dummy_config.oidc_rp_idp_sign_key = ""
    dummy_config.oidc_op_jwks_endpoint = ""
    dummy_config.save()
    backend = OIDCAuthenticationBackend()
    backend.config_class = type(dummy_config)

    with pytest.raises(ImproperlyConfigured):
        backend.OIDC_RP_CLIENT_ID  # the exact setting doesn't matter

    # check that the same error is raised by the upstream backend
    settings.OIDC_RP_SIGN_ALGO = sign_alg
    settings.OIDC_RP_IDP_SIGN_KEY = None
    settings.OIDC_OP_JWKS_ENDPOINT = None
    with pytest.raises(ImproperlyConfigured):
        UpstreamBackend()


#
# LOGGING AND OBFUSCATION TESTS
#


class SensitiveClaimsConfig(OpenIDConnectConfig):
    class Meta:
        proxy = True
        app_label = "mozilla_django_oidc_db"

    sensitive_claims = (
        ["sensitive_claim1"],
        ["parent", "sensitive_claim2"],
    )


@pytest.mark.callback_request(
    init_view=OIDCAuthenticationRequestView.as_view(config_class=SensitiveClaimsConfig)
)
@pytest.mark.oidcconfig(enabled=True, username_claim=["sub"])
def test_obfuscates_sensitive_claims(
    dummy_config, callback_request: HttpRequest, caplog
):
    caplog.set_level(logging.DEBUG, logger="mozilla_django_oidc_db.backends")
    backend = OIDCAuthenticationBackend()
    backend.request = callback_request
    backend.config_class = lookup_config(callback_request)

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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["sub"],
)
def test_case_insensitive_username_lookups(
    settings, dummy_config, callback_request: HttpRequest
):
    settings.OIDCDB_USERNAME_CASE_SENSITIVE = False
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["user", "username"],
    groups_claim=["user", "groups.names"],
    claim_mapping={
        "email": ["attributes.email"],
        "first_name": ["profile", "given_name"],
        "last_name": ["profile", "family_name"],
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["user", "username"],
    groups_claim=["user", "groups.names"],
    sync_groups=True,
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["sub"],
    groups_claim=["roles"],
    sync_groups=True,
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["user", "username"],
    groups_claim=["user", "groups.names"],
    claim_mapping={
        "email": ["attributes.email"],
        "first_name": ["profile", "given_name"],
        "last_name": ["profile", "family_name"],
    },
    sync_groups=True,
    sync_groups_glob_pattern="*",
)
def test_update_user_with_custom_and_complex_config(
    dummy_config, callback_request: HttpRequest
):
    # explicitly clear to wipe any possible implicit defaults
    dummy_config.default_groups.clear()
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    groups_claim=[],
    sync_groups=True,
    sync_groups_glob_pattern="*",
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    groups_claim=["roles"],
    sync_groups=True,
    sync_groups_glob_pattern="myapp:*",
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    groups_claim=["roles"],
    sync_groups=True,
    sync_groups_glob_pattern="myapp:*",
)
def test_authenticate_user_groups_and_default_groups(
    dummy_config, callback_request: HttpRequest
):
    default_group = Group.objects.create(name="default1")
    Group.objects.create(name="default2")
    dummy_config.default_groups.set({default_group})
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    make_users_staff=True,
    claim_mapping={
        "is_superuser": ["is_god"],
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    make_users_staff=True,
    sync_groups=False,
    groups_claim=["roles"],
    superuser_group_names=["superuser"],
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    make_users_staff=True,
    sync_groups=False,
    groups_claim=["roles"],
    superuser_group_names=["superuser"],
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


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    make_users_staff=True,
    sync_groups=False,
    groups_claim=["roles"],
    superuser_group_names=[],
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


@pytest.mark.oidcconfig(enabled=True)
def test_authenticate_called_without_args(dummy_config):
    backend = OIDCAuthenticationBackend()

    user = backend.authenticate(request=None)

    assert user is None


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["sub"],
)
def test_username_claim_empty(dummy_config, callback_request: HttpRequest):
    backend = MockBackend(claims={"sub": ""})

    user = backend.authenticate(request=callback_request)

    assert user is None


@pytest.mark.oidcconfig(
    enabled=True, userinfo_claims_source=UserInformationClaimsSources.id_token
)
def test_empty_claims(dummy_config, callback_request: HttpRequest):
    backend = MockBackend(claims={})

    user = backend.authenticate(request=callback_request)

    assert user is None


@pytest.mark.oidcconfig(
    enabled=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    username_claim=["sub"],
    groups_claim=["roles"],
    sync_groups=True,
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

    * assertion fails because get_solo was called
    * pytest will complain about database access which is forbidden because there is
      no pytest.mark.django_db present (deliberately)
    """
    m_get_setting = mocker.patch(
        "mozilla_django_oidc_db.backends.get_setting_from_config"
    )

    # instantiate
    OIDCAuthenticationBackend()

    m_get_setting.assert_not_called()
