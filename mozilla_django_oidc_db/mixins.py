from mozilla_django_oidc.utils import import_from_settings

from .models import OpenIDConnectConfig


class SoloConfigMixin:
    config_class = OpenIDConnectConfig

    @property
    def config(self):
        # See https://github.com/maykinmedia/mozilla-django-oidc-db/issues/51
        # Using getattr here, because `GetAttributeMixin` causes any get operation to
        # always return `None` as a default, causing `hasattr(self, "_solo_config")` to
        # evaluate to True
        if not getattr(self, "_solo_config", None):
            self._solo_config = self.config_class.get_solo()
        return self._solo_config

    def refresh_config(self):
        """
        Refreshes the cached config on the instance, required for middleware
        since middleware is only instantiated once (during the Django startup phase)
        """
        if getattr(self, "_solo_config", None):
            del self._solo_config

    def get_settings(self, attr, *args):
        attr_lowercase = attr.lower()
        if hasattr(self.config, attr_lowercase):
            # Workaround for OIDC_RP_IDP_SIGN_KEY being an empty string by default.
            # mozilla-django-oidc explicitly checks if `OIDC_RP_IDP_SIGN_KEY` is not `None`
            # https://github.com/mozilla/mozilla-django-oidc/blob/master/mozilla_django_oidc/auth.py#L189
            value_from_config = getattr(self.config, attr_lowercase)
            if value_from_config == "":
                return None
            return value_from_config
        return import_from_settings(attr, *args)


class GetAttributeMixin:
    def __getattribute__(self, attr):
        """
        Mixin used to avoid calls to the config model on __init__ and instead
        do these calls runtime
        """
        try:
            default = super().__getattribute__(attr)
        except AttributeError:
            default = None

        if attr.startswith("OIDC"):
            return self.get_settings(attr, default)
        return default
