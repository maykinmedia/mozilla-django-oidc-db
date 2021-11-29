from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import RequestFactory

import pytest

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.models import OpenIDConnectConfig


@pytest.mark.django_db
def test_backend_authenticate_oidc_not_enabled():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = False
    config.save()

    backend = OIDCAuthenticationBackend()

    request = RequestFactory().get("/")

    # Authentication with the backend should not return a result,
    # because OIDC is not enabled
    assert backend.authenticate(request) is None


@pytest.mark.django_db
def test_backend_get_user_instance_values():
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


@pytest.mark.django_db
def test_backend_create_user():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.oidc_rp_client_id = "testid"
    config.oidc_rp_client_secret = "secret"
    config.oidc_rp_sign_algo = "HS256"
    config.oidc_rp_scopes_list = ["openid", "email"]
    config.oidc_op_jwks_endpoint = "http://some.endpoint/v1/jwks"
    config.oidc_op_authorization_endpoint = "http://some.endpoint/v1/auth"
    config.oidc_op_token_endpoint = "http://some.endpoint/v1/token"
    config.oidc_op_user_endpoint = "http://some.endpoint/v1/user"
    config.save()

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
def test_backend_create_user_different_username_claim():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.oidc_rp_client_id = "testid"
    config.oidc_rp_client_secret = "secret"
    config.oidc_rp_sign_algo = "HS256"
    config.oidc_rp_scopes_list = ["openid", "email"]
    config.oidc_op_jwks_endpoint = "http://some.endpoint/v1/jwks"
    config.oidc_op_authorization_endpoint = "http://some.endpoint/v1/auth"
    config.oidc_op_token_endpoint = "http://some.endpoint/v1/token"
    config.oidc_op_user_endpoint = "http://some.endpoint/v1/user"
    config.username_claim = "upn"
    config.save()

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
def test_backend_filter_users():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.oidc_rp_client_id = "testid"
    config.oidc_rp_client_secret = "secret"
    config.oidc_rp_sign_algo = "HS256"
    config.oidc_rp_scopes_list = ["openid", "email"]
    config.oidc_op_jwks_endpoint = "http://some.endpoint/v1/jwks"
    config.oidc_op_authorization_endpoint = "http://some.endpoint/v1/auth"
    config.oidc_op_token_endpoint = "http://some.endpoint/v1/token"
    config.oidc_op_user_endpoint = "http://some.endpoint/v1/user"
    config.username_claim = "sub"
    config.save()

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
def test_backend_filter_users_different_username_claim():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.oidc_rp_client_id = "testid"
    config.oidc_rp_client_secret = "secret"
    config.oidc_rp_sign_algo = "HS256"
    config.oidc_rp_scopes_list = ["openid", "email"]
    config.oidc_op_jwks_endpoint = "http://some.endpoint/v1/jwks"
    config.oidc_op_authorization_endpoint = "http://some.endpoint/v1/auth"
    config.oidc_op_token_endpoint = "http://some.endpoint/v1/token"
    config.oidc_op_user_endpoint = "http://some.endpoint/v1/user"
    config.username_claim = "upn"
    config.save()

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
def test_backend_update_user():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.oidc_rp_client_id = "testid"
    config.oidc_rp_client_secret = "secret"
    config.oidc_rp_sign_algo = "HS256"
    config.oidc_rp_scopes_list = ["openid", "email"]
    config.oidc_op_jwks_endpoint = "http://some.endpoint/v1/jwks"
    config.oidc_op_authorization_endpoint = "http://some.endpoint/v1/auth"
    config.oidc_op_token_endpoint = "http://some.endpoint/v1/token"
    config.oidc_op_user_endpoint = "http://some.endpoint/v1/user"
    config.username_claim = "sub"
    config.save()

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


@pytest.mark.django_db
def test_backend_create_user_sync_all_groups():
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.groups_claim = "roles"
    config.sync_groups = True
    config.sync_groups_glob_pattern = "*"
    config.save()

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
def test_backend_create_user_sync_groups_according_to_pattern():
    Group.objects.all().delete()
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.groups_claim = "roles"
    config.sync_groups = True
    config.sync_groups_glob_pattern = "group*"
    config.save()

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
def test_backend_create_user_with_profile_settings():
    Group.objects.all().delete()
    config = OpenIDConnectConfig.get_solo()

    config.enabled = True
    config.groups_claim = "roles"
    config.sync_groups = True
    config.claim_mapping = {
        "first_name": "given_name",
        "last_name": "family_name",
        "email": "email",
        "is_superuser": "is_god",
    }
    config.sync_groups_glob_pattern = "*"
    config.make_users_staff = True
    config.save()

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
