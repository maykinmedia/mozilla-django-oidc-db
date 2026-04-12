"""
Tests for the OIDC account-merge onboarding flow (issue #122).

The flow is triggered when:
- ``allow_account_merge`` is enabled on the OIDCClient
- The OIDC username claim does not match any existing Django user
- But the OIDC email claim *does* match an existing Django user (same email)

The user is redirected to a password-confirmation form, and on success the
existing user's username is renamed to the OIDC identifier and the local
password is cleared.
"""

from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse

import pytest

from mozilla_django_oidc_db.exceptions import AccountMergeRequired
from mozilla_django_oidc_db.models import UserInformationClaimsSources
from mozilla_django_oidc_db.registry import register as registry
from mozilla_django_oidc_db.views import (
    _OIDC_MERGE_CANDIDATE_PK_KEY,
    _OIDC_MERGE_CLAIMS_KEY,
    _OIDC_MERGE_CONFIG_KEY,
)
from testapp.backends import MockBackend

from .conftest import callback_request_mark as callback_request, oidcconfig
from .factories import UserFactory


# ---------------------------------------------------------------------------
# Fixtures shared across callback-level tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_auth_backend(request, mocker):
    """Patch Django auth backends with a MockBackend using the given claims."""
    marker = request.node.get_closest_marker("mock_backend_claims")
    claims = marker.args[0] if marker else {"sub": "some_username"}
    mock_backend = MockBackend(claims=claims)
    backend_path = f"{MockBackend.__module__}.{MockBackend.__qualname__}"
    mocker.patch(
        "django.contrib.auth._get_backends",
        return_value=[(mock_backend, backend_path)],
    )
    return mock_backend


@pytest.fixture
def callback_client(callback_request, client: Client) -> Client:
    """A test client whose session is pre-populated from the OIDC auth request."""
    session = client.session
    for key, value in callback_request.session.items():
        session[key] = value
    session.save()
    return client


mock_backend_claims = pytest.mark.mock_backend_claims


# ---------------------------------------------------------------------------
# Plugin-level tests
# ---------------------------------------------------------------------------


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_create_user_raises_account_merge_required_when_email_matches(dummy_config):
    """AccountMergeRequired is raised when the email claim matches an existing user."""
    existing = UserFactory.create(username="existing-local", email="user@example.com")
    plugin = registry["test-oidc"]

    with pytest.raises(AccountMergeRequired) as exc_info:
        plugin.create_user(
            claims={"sub": "oidc-uuid-sub", "email": "user@example.com"}
        )

    assert exc_info.value.candidate == existing
    assert exc_info.value.claims["sub"] == "oidc-uuid-sub"


@oidcconfig(
    enabled=True,
    allow_account_merge=False,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_create_user_does_not_raise_when_merge_disabled(dummy_config):
    """No AccountMergeRequired when allow_account_merge is False (default)."""
    UserFactory.create(username="existing-local", email="user@example.com")
    plugin = registry["test-oidc"]

    # Should create a new user, not raise.
    user = plugin.create_user(
        claims={"sub": "oidc-uuid-sub", "email": "user@example.com"}
    )

    assert user.username == "oidc-uuid-sub"
    assert User.objects.count() == 2


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_create_user_no_raise_when_no_email_match(dummy_config):
    """No AccountMergeRequired when the email does not match any existing user."""
    plugin = registry["test-oidc"]

    user = plugin.create_user(
        claims={"sub": "oidc-uuid-sub", "email": "new@example.com"}
    )

    assert user.username == "oidc-uuid-sub"


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": [],  # explicitly no email claim path
    },
)
@pytest.mark.django_db
def test_create_user_no_raise_when_no_email_claim_configured(dummy_config):
    """No AccountMergeRequired when no email claim path is configured."""
    UserFactory.create(username="existing-local", email="user@example.com")
    plugin = registry["test-oidc"]

    user = plugin.create_user(
        claims={"sub": "oidc-uuid-sub", "email": "user@example.com"}
    )

    assert user.username == "oidc-uuid-sub"


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
        "user_settings.claim_mappings.first_name": ["given_name"],
    },
)
@pytest.mark.django_db
def test_merge_accounts_renames_username_and_clears_password(dummy_config):
    """merge_accounts renames the username and sets an unusable password."""
    existing = UserFactory.create(
        username="existing-local",
        email="user@example.com",
        first_name="Old",
    )
    existing.set_password("secret123")
    existing.save()

    plugin = registry["test-oidc"]
    merged = plugin.merge_accounts(
        existing,
        claims={
            "sub": "oidc-uuid-sub",
            "email": "user@example.com",
            "given_name": "New",
        },
    )

    merged.refresh_from_db()
    assert merged.pk == existing.pk  # same record
    assert merged.username == "oidc-uuid-sub"
    assert not merged.has_usable_password()
    assert merged.first_name == "New"


# ---------------------------------------------------------------------------
# Callback-view-level tests: redirect to merge view
# ---------------------------------------------------------------------------


@mock_backend_claims({"sub": "oidc-uuid", "email": "user@example.com"})
@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    userinfo_claims_source=UserInformationClaimsSources.id_token,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_callback_redirects_to_merge_view_on_email_clash(
    dummy_config,
    callback_request,
    callback_client: Client,
    mock_auth_backend,
):
    """
    When an email clash is detected the callback view redirects to the
    account-merge URL and stores the necessary state in the session.
    """
    existing = UserFactory.create(username="existing-local", email="user@example.com")

    callback_url = reverse("oidc_authentication_callback")
    response = callback_client.get(callback_url, {**callback_request.GET})

    assert response.status_code == 302
    assert response["Location"] == reverse("admin-oidc-account-merge")

    session = callback_client.session
    assert session[_OIDC_MERGE_CANDIDATE_PK_KEY] == existing.pk
    assert session[_OIDC_MERGE_CLAIMS_KEY]["sub"] == "oidc-uuid"
    assert session[_OIDC_MERGE_CONFIG_KEY] == "test-oidc"


# ---------------------------------------------------------------------------
# Merge view (form) tests
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_merge_view_inaccessible_without_session_state(client):
    """Direct access to the merge URL without a pending merge raises 403."""
    response = client.get(reverse("admin-oidc-account-merge"))
    assert response.status_code == 403


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_merge_view_wrong_password_shows_error(client, dummy_config):
    """Submitting a wrong password re-renders the form with an error."""
    existing = UserFactory.create(username="local-user", email="u@example.com")
    existing.set_password("correct-password")
    existing.save()

    session = client.session
    session[_OIDC_MERGE_CANDIDATE_PK_KEY] = existing.pk
    session[_OIDC_MERGE_CLAIMS_KEY] = {"sub": "oidc-uuid", "email": "u@example.com"}
    session[_OIDC_MERGE_CONFIG_KEY] = "test-oidc"
    session.save()

    response = client.post(
        reverse("admin-oidc-account-merge"),
        data={"password": "wrong-password"},
    )

    assert response.status_code == 200
    assert "Incorrect password" in response.content.decode()
    # User must NOT be merged.
    existing.refresh_from_db()
    assert existing.username == "local-user"
    assert existing.has_usable_password()


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_merge_view_correct_password_merges_and_logs_in(client, dummy_config):
    """Correct password triggers the merge and logs the user in."""
    existing = UserFactory.create(username="local-user", email="u@example.com")
    existing.set_password("correct-password")
    existing.save()

    session = client.session
    session[_OIDC_MERGE_CANDIDATE_PK_KEY] = existing.pk
    session[_OIDC_MERGE_CLAIMS_KEY] = {"sub": "oidc-uuid", "email": "u@example.com"}
    session[_OIDC_MERGE_CONFIG_KEY] = "test-oidc"
    session.save()

    response = client.post(
        reverse("admin-oidc-account-merge"),
        data={"password": "correct-password"},
        follow=False,
    )

    assert response.status_code == 302

    existing.refresh_from_db()
    assert existing.username == "oidc-uuid"
    assert not existing.has_usable_password()

    # Session merge keys must be cleaned up.
    updated_session = client.session
    assert _OIDC_MERGE_CANDIDATE_PK_KEY not in updated_session
    assert _OIDC_MERGE_CLAIMS_KEY not in updated_session
    assert _OIDC_MERGE_CONFIG_KEY not in updated_session


@oidcconfig(
    enabled=True,
    allow_account_merge=True,
    extra_options={
        "user_settings.claim_mappings.username": ["sub"],
        "user_settings.claim_mappings.email": ["email"],
    },
)
@pytest.mark.django_db
def test_merge_view_redirects_to_return_url(client, dummy_config):
    """After a successful merge the user is redirected to the stored return URL."""
    from mozilla_django_oidc_db.views import _RETURN_URL_SESSION_KEY

    existing = UserFactory.create(username="local-user", email="u@example.com")
    existing.set_password("pw")
    existing.save()

    session = client.session
    session[_OIDC_MERGE_CANDIDATE_PK_KEY] = existing.pk
    session[_OIDC_MERGE_CLAIMS_KEY] = {"sub": "oidc-uuid", "email": "u@example.com"}
    session[_OIDC_MERGE_CONFIG_KEY] = "test-oidc"
    session[_RETURN_URL_SESSION_KEY] = "/admin/"
    session.save()

    response = client.post(
        reverse("admin-oidc-account-merge"),
        data={"password": "pw"},
        follow=False,
    )

    assert response.status_code == 302
    assert response["Location"] == "/admin/"
