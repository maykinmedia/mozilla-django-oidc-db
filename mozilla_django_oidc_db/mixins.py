import warnings
from typing import Any, ClassVar, Generic, TypeVar, cast

from .config import get_setting_from_config
from .models import OpenIDConnectConfig, OpenIDConnectConfigBase

T = TypeVar("T", bound=OpenIDConnectConfigBase)


class SoloConfigMixin(Generic[T]):
    config_class: ClassVar[type[OpenIDConnectConfigBase]] = OpenIDConnectConfig
    _solo_config: T

    @property
    def config(self) -> T:
        if not hasattr(self, "_solo_config"):
            # django-solo and type checking is challenging, but a new release is on the
            # way and should fix that :fingers_crossed:
            config = self.config_class.get_solo()
            self._solo_config = cast(T, config)
        return self._solo_config

    def refresh_config(self) -> None:
        """
        Refreshes the cached config on the instance, required for middleware
        since middleware is only instantiated once (during the Django startup phase)
        """
        if hasattr(self, "_solo_config"):
            del self._solo_config

    def get_settings(self, attr: str, *args: Any):
        return get_setting_from_config(self.config, attr, *args)


class GetAttributeMixin:
    def __getattribute__(self, attr: str):
        """
        Mixin used to avoid calls to the config model on __init__ and instead
        do these calls runtime
        """
        if not attr.startswith("OIDC"):
            return super().__getattribute__(attr)

        warnings.warn(
            "GetAttributeMixin will be deprecated, instead use an explicit descriptor",
            category=PendingDeprecationWarning,
            stacklevel=2,
        )

        try:
            default = super().__getattribute__(attr)
        except AttributeError:
            default = None
        return self.get_settings(attr, default)
