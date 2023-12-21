from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import RequestFactory

import pytest

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.models import OpenIDConnectConfig


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_authenticate_oidc_not_enabled(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(enabled=False)

    backend = OIDCAuthenticationBackend()

    request = RequestFactory().get("/")

    # Authentication with the backend should not return a result,
    # because OIDC is not enabled
    assert backend.authenticate(request) is None


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_get_sensitive_claims(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(enabled=True, username_claim="sub")

    class CustomOIDCBackend(OIDCAuthenticationBackend):
        sensitive_claim_names = ["sensitive_claim1", "sensitive_claim2"]

    backend = CustomOIDCBackend()

    # Only the sensitive claims + the identifier claim should be obfuscated
    assert backend.get_sensitive_claims_names() == [
        "sub",
        "sensitive_claim1",
        "sensitive_claim2",
    ]


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_get_user_instance_values(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        claim_mapping=OpenIDConnectConfig._meta.get_field("claim_mapping").get_default()
    )

    claims = {
        "sub": "123456",
        "email": "admin@localhost",
        "given_name": "John",
        "family_name": "Doe",
    }

    backend = OIDCAuthenticationBackend()

    user_values = backend.get_user_instance_values(claims)

    assert user_values == {
        "email": "admin@localhost",
        "first_name": "John",
        "last_name": "Doe",
    }


@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_get_user_instance_values_nested_claims(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        claim_mapping={
            "email": "user_info.email",
            "first_name": "user_info.given_name",
            "last_name": "user_info.family_name",
        }
    )

    claims = {
        "sub": "123456",
        "user_info": {
            "email": "admin@localhost",
            "given_name": "John",
            "family_name": "Doe",
        },
    }

    backend = OIDCAuthenticationBackend()

    user_values = backend.get_user_instance_values(claims)

    assert user_values == {
        "email": "admin@localhost",
        "first_name": "John",
        "last_name": "Doe",
    }


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
    )

    User = get_user_model()

    claims = {
        "sub": "123456",
        "email": "admin@localhost",
        "given_name": "John",
        "family_name": "Doe",
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_different_username_claim(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        username_claim="upn",
    )

    User = get_user_model()

    claims = {
        "sub": "123456",
        "upn": "admin",
        "email": "admin@localhost",
        "given_name": "John",
        "family_name": "Doe",
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify `upn` is used as username
    assert user.username == "admin"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_filter_users(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        username_claim="sub",
    )

    User = get_user_model()

    # Create two users with the same email address, this shouldn't cause problems
    user1 = User.objects.create(
        username="123456", email="admin@localhost", first_name="John", last_name="Doe"
    )
    user2 = User.objects.create(
        username="654321", email="admin@localhost", first_name="Jane", last_name="Doe"
    )

    claims = {
        "sub": "123456",
        "email": "admin@localhost",
        "given_name": "John",
        "family_name": "Doe",
    }

    backend = OIDCAuthenticationBackend()

    users = backend.filter_users_by_claims(claims)

    assert users.count() == 1

    user = users.first()

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_filter_users_different_username_claim(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        username_claim="upn",
    )

    User = get_user_model()

    # Create two users with the same email address, this shouldn't cause problems
    user1 = User.objects.create(
        username="admin", email="admin@localhost", first_name="John", last_name="Doe"
    )
    user2 = User.objects.create(
        username="admin2", email="admin@localhost", first_name="Jane", last_name="Doe"
    )

    claims = {
        "upn": "admin2",
        "email": "admin@localhost",
        "given_name": "Jane",
        "family_name": "Doe",
    }

    backend = OIDCAuthenticationBackend()

    users = backend.filter_users_by_claims(claims)

    assert users.count() == 1

    user = users.first()

    # Verify that a user is created with the correct values
    assert user.username == "admin2"
    assert user.email == "admin@localhost"
    assert user.first_name == "Jane"
    assert user.last_name == "Doe"


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_update_user(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        username_claim="sub",
    )

    User = get_user_model()

    # Create two users with the same email address, this shouldn't cause problems
    # is_superuser should not be affected if `superuser_group_names` is not set
    user1 = User.objects.create(
        username="123456",
        email="admin@localhost",
        first_name="John",
        last_name="Doe",
        is_superuser=True,
    )
    user2 = User.objects.create(
        username="654321", email="admin@localhost", first_name="Jane", last_name="Doe"
    )

    claims = {
        "sub": "123456",
        "email": "modified@localhost",
        "given_name": "Name",
        "family_name": "Modified",
    }

    backend = OIDCAuthenticationBackend()

    user = backend.update_user(user1, claims)

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert user.email == "modified@localhost"
    assert user.first_name == "Name"
    assert user.last_name == "Modified"
    assert user.is_superuser


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_sync_all_groups(mock_get_solo):
    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=True,
        sync_groups_glob_pattern="*",
    )
    # Explicitly set to none
    oidc_config.default_groups.set(Group.objects.none())
    mock_get_solo.return_value = oidc_config

    claims = {
        "sub": "123456",
        "roles": ["useradmin", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that the groups were created
    assert Group.objects.count() == 2

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert list(user.groups.values_list("name", flat=True)) == [
        "useradmin",
        "groupadmin",
    ]


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_sync_groups_according_to_pattern(mock_get_solo):
    Group.objects.all().delete()

    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=True,
        sync_groups_glob_pattern="group*",
    )
    # Explicitly set to none
    oidc_config.default_groups.set(Group.objects.none())
    mock_get_solo.return_value = oidc_config

    claims = {
        "sub": "123456",
        "roles": ["useradmin", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert list(user.groups.values_list("name", flat=True)) == ["groupadmin"]


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_sync_all_groups_nested_groups_claim(mock_get_solo):
    mock_get_solo.return_value = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="nested_object.roles",
        sync_groups=True,
        sync_groups_glob_pattern="*",
    )

    claims = {
        "sub": "123456",
        "nested_object": {"roles": ["useradmin", "groupadmin"]},
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that the groups were created
    assert Group.objects.count() == 2

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert list(user.groups.values_list("name", flat=True)) == [
        "useradmin",
        "groupadmin",
    ]


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_sync_all_groups_and_default_groups(mock_get_solo):
    Group.objects.all().delete()

    default1 = Group.objects.create(name="default1")
    default2 = Group.objects.create(name="default2")
    Group.objects.create(name="other")

    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=True,
        sync_groups_glob_pattern="*",
    )
    oidc_config.save()
    oidc_config.default_groups.set([default1, default2])
    mock_get_solo.return_value = oidc_config

    claims = {
        "sub": "123456",
        "roles": ["useradmin", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert list(user.groups.values_list("name", flat=True)) == [
        "default1",
        "default2",
        "useradmin",
        "groupadmin",
    ]


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_sync_groups_according_to_pattern_and_default_groups(
    mock_get_solo,
):
    Group.objects.all().delete()

    default1 = Group.objects.create(name="default1")
    default2 = Group.objects.create(name="default2")
    Group.objects.create(name="other")

    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=True,
        sync_groups_glob_pattern="group*",
    )
    oidc_config.save()
    oidc_config.default_groups.set([default1, default2])
    mock_get_solo.return_value = oidc_config

    claims = {
        "sub": "123456",
        "roles": ["useradmin", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert list(user.groups.values_list("name", flat=True)) == [
        "default1",
        "default2",
        "groupadmin",
    ]


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_create_user_with_profile_settings(mock_get_solo):
    Group.objects.all().delete()

    mock_get_solo.return_value = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=True,
        claim_mapping={
            "first_name": "given_name",
            "last_name": "family_name",
            "email": "email",
            "is_superuser": "is_god",
        },
        sync_groups_glob_pattern="*",
        make_users_staff=True,
    )

    Group.objects.create(name="useradmin")
    Group.objects.create(name="groupadmin")

    claims = {
        "sub": "123456",
        "email": "admin@localhost",
        "given_name": "John",
        "family_name": "Doe",
        "is_god": 1,
        "roles": [
            "useradmin",
        ],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert user.email == "admin@localhost"
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.is_staff == True
    assert user.is_superuser == True
    assert list(user.groups.values_list("name", flat=True)) == ["useradmin"]


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_init_cache_not_called(mock_get_solo):
    """
    Regression test for https://github.com/maykinmedia/mozilla-django-oidc-db/issues/30
    """

    mock_get_solo.return_value = OpenIDConnectConfig(enabled=False)

    User = get_user_model()
    user = User.objects.create(
        username="123456", email="admin@localhost", first_name="John", last_name="Doe"
    )

    with patch(
        "mozilla_django_oidc_db.backends.OIDCAuthenticationBackend",
        side_effect=OIDCAuthenticationBackend,
    ) as mock_init:
        # `User.has_perm` should cause all backends to be instantiated
        user.has_perm("test")

        assert mock_init.call_count == 1

    # `OpenIDConnectConfig.get_solo` should not be called when initializing the backend
    assert mock_get_solo.call_count == 0


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_update_user_superuser(mock_get_solo):
    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=False,
        superuser_group_names=["superuser"],
    )
    mock_get_solo.return_value = oidc_config

    claims = {
        "sub": "123456",
        "roles": ["superuser", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.create_user(claims)

    # Verify that the groups were created
    assert Group.objects.count() == 0

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert user.is_superuser


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_update_user_remove_superuser(mock_get_solo):
    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=False,
        superuser_group_names=["superuser"],
    )
    mock_get_solo.return_value = oidc_config

    User = get_user_model()
    user = User.objects.create(
        username="123456",
        email="admin@localhost",
        first_name="John",
        last_name="Doe",
        is_superuser=True,
    )

    claims = {
        "sub": "123456",
        "roles": ["nosuperuser", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.update_user(user, claims)

    # Verify that the groups were created
    assert Group.objects.count() == 0

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert not user.is_superuser


@pytest.mark.django_db
@patch("mozilla_django_oidc_db.models.OpenIDConnectConfig.get_solo")
def test_backend_update_user_no_superuser_group_names(
    mock_get_solo,
):
    oidc_config = OpenIDConnectConfig(
        id=1,
        enabled=True,
        oidc_rp_client_id="testid",
        oidc_rp_client_secret="secret",
        oidc_rp_sign_algo="HS256",
        oidc_rp_scopes_list=["openid", "email"],
        oidc_op_jwks_endpoint="http://some.endpoint/v1/jwks",
        oidc_op_authorization_endpoint="http://some.endpoint/v1/auth",
        oidc_op_token_endpoint="http://some.endpoint/v1/token",
        oidc_op_user_endpoint="http://some.endpoint/v1/user",
        groups_claim="roles",
        sync_groups=False,
        superuser_group_names=[],
    )
    mock_get_solo.return_value = oidc_config

    User = get_user_model()
    user = User.objects.create(
        username="123456",
        email="admin@localhost",
        first_name="John",
        last_name="Doe",
        is_superuser=True,
    )

    claims = {
        "sub": "123456",
        "roles": ["nosuperuser", "groupadmin"],
    }

    backend = OIDCAuthenticationBackend()

    user = backend.update_user(user, claims)

    # Verify that the groups were created
    assert Group.objects.count() == 0

    # Verify that a user is created with the correct values
    assert user.username == "123456"
    assert user.is_superuser
