from mozilla_django_oidc.utils import import_from_settings

from .models import OpenIDConnectConfig


class SoloConfigMixin:
    config_class = OpenIDConnectConfig

    @property
    def config(self):
        if not hasattr(self, "_solo_config"):
            self._solo_config = self.config_class.get_solo()
        return self._solo_config

    def refresh_config(self):
        """
        Refreshes the cached config on the instance, required for middleware
        since middleware is only instantiated once (during the Django startup phase)
        """
        if hasattr(self, "_solo_config"):
            del self._solo_config

    def get_settings(self, attr, *args):
        attr_lowercase = attr.lower()
        if getattr(self.config, attr_lowercase, ""):
            return getattr(self.config, attr_lowercase)
        return import_from_settings(attr, *args)
