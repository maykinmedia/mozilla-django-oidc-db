from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

import pytest

from mozilla_django_oidc_db.fields import ClaimFieldDefault
from mozilla_django_oidc_db.models import OpenIDConnectConfig


def test_default_cache_key():
    assert (
        OpenIDConnectConfig.get_cache_key()
        == "solo:mozilla_django_oidc_db:openidconnectconfig"
    )


def test_different_default_provided(settings):
    settings.MOZILLA_DJANGO_OIDC_DB_PREFIX = "otherprefix"
    assert (
        OpenIDConnectConfig.get_cache_key()
        == "otherprefix:mozilla_django_oidc_db:openidconnectconfig"
    )


@pytest.fixture()
def unset_oidc_cache_prefix(settings):
    del settings.MOZILLA_DJANGO_OIDC_DB_PREFIX


def test_validate_claim_mapping_fields():
    instance = OpenIDConnectConfig(
        claim_mapping={
            "bad_field_no_cookie": ["har"],
        }
    )

    with pytest.raises(ValidationError) as exc_context:
        instance.clean()

    err_dict = exc_context.value.message_dict
    assert "claim_mapping" in err_dict
    error = _("Field '{field}' does not exist on the user model").format(
        field="bad_field_no_cookie"
    )
    assert error in err_dict["claim_mapping"]


def test_validate_username_field_not_in_claim_mapping():
    instance = OpenIDConnectConfig(
        claim_mapping={
            "username": ["nope"],
        }
    )

    with pytest.raises(ValidationError) as exc_context:
        instance.clean()

    err_dict = exc_context.value.message_dict
    assert "claim_mapping" in err_dict
    error = _("The username field may not be in the claim mapping")
    assert error in err_dict["claim_mapping"]


def test_claim_field_default_equality():
    assert ClaimFieldDefault("foo", "bar") == ClaimFieldDefault("foo", "bar")
    assert ClaimFieldDefault("foo", "bar") != ClaimFieldDefault("bar", "foo")
