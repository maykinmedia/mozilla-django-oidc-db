"""
Helpers to work with (dynamic) OIDC configuration.

The utilities here make it easier to work with configuration that lives on a
configuration model instance rather than in Django settings, while also handling
settings that are still defined in the django settings layer.
"""

from typing import Any

from mozilla_django_oidc.utils import import_from_settings

from .models import OpenIDConnectConfigBase


def get_setting_from_config(config: OpenIDConnectConfigBase, attr: str, *args) -> Any:
    """
    Look up a setting from the config record or fall back to Django settings.

    Django settings are defined as ``OIDC_SOME_SETTING``, in upper case, while our
    model fields typically match the name, but in lower case. So, we look up if the
    requested setting exists as an attribut on the configuration instance and use that
    when provided, otherwise we fall back to the django settings module.

    .. note:: A setting may also be defined as a (calculated) property of some kind on
       a/the configuration instance, rather than an explicit model field. That's why
       we use ``hasattr`` checks rather than relying on
       ``config._meta.get_field(some_field)``.
    """
    attr_lowercase = attr.lower()
    if hasattr(config, attr_lowercase):
        # Workaround for OIDC_RP_IDP_SIGN_KEY being an empty string by default.
        # mozilla-django-oidc explicitly checks if `OIDC_RP_IDP_SIGN_KEY` is not `None`
        # https://github.com/mozilla/mozilla-django-oidc/blob/master/mozilla_django_oidc/auth.py#L189
        if (value_from_config := getattr(config, attr_lowercase)) == "":
            return None
        return value_from_config
    return import_from_settings(attr, *args)
