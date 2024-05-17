"""
Helpers for tests dealing with custom configuration flows.

This uses proxy models to modify behaviour without needing to apply @isolate_apps.
"""

from mozilla_django_oidc_db.models import OpenIDConnectConfig
from mozilla_django_oidc_db.views import OIDCInit

__all__ = ["CustomConfig", "oidc_init", "oidc_init_disabled"]


class static_setting:
    def __init__(self, val):
        self.val = val

    def __get__(self, obj, objtype):
        return self.val

    def __set__(self, obj, val):
        pass


class CustomConfig(OpenIDConnectConfig):
    class Meta:
        proxy = True
        app_label = "mozilla_django_oidc_db"

    enabled = static_setting(True)
    oidc_rp_client_id = static_setting("fixed_client_id")
    oidc_rp_client_secret = static_setting("supersecret")
    oidc_op_authorization_endpoint = static_setting("https://example.com/oidc/auth")


class DisabledConfig(OpenIDConnectConfig):
    class Meta:
        proxy = True
        app_label = "mozilla_django_oidc_db"

    enabled = static_setting(False)


oidc_init = OIDCInit.as_view(config_class=CustomConfig, allow_next_from_query=False)
oidc_init_disabled = OIDCInit.as_view(config_class=DisabledConfig)
