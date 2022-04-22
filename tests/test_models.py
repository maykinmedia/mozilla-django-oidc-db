from django.test.utils import isolate_apps

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
