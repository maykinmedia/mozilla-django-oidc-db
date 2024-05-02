from django.core.exceptions import ValidationError
from django.test.utils import isolate_apps
from django.utils.translation import gettext as _

import pytest

from mozilla_django_oidc_db.models import OpenIDConnectConfig, classproperty


def test_default_cache_key():
    assert OpenIDConnectConfig.get_cache_key() == "oidc:openidconnectconfig"


@isolate_apps("testapp")
def test_override_cache_key_with_class():
    class CustomConfig(OpenIDConnectConfig):
        class Meta:
            app_label = "custom"

        @classproperty
        def custom_oidc_db_prefix(cls):
            return "custom"

    assert CustomConfig.get_cache_key() == "custom:customconfig"


@isolate_apps("testapp")
def test_custom_config_override_cache_key_with_settings():
    class CustomConfig(OpenIDConnectConfig):
        class Meta:
            app_label = "custom"

        @classproperty
        def custom_oidc_db_prefix(cls):
            return ""

    # Prefix taken from `testapp/settings.py`
    assert CustomConfig.get_cache_key() == "default:customconfig"


@pytest.fixture()
def unset_oidc_cache_prefix(settings):
    del settings.MOZILLA_DJANGO_OIDC_DB_PREFIX


@isolate_apps("testapp")
def test_custom_config_cache_key_fallback(unset_oidc_cache_prefix):
    class CustomConfig(OpenIDConnectConfig):
        class Meta:
            app_label = "custom"

        @classproperty
        def custom_oidc_db_prefix(cls):
            return ""

    # Prefix taken from `mozilla_django_oidc_dv/settings.py`
    assert CustomConfig.get_cache_key() == "oidc:customconfig"


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
