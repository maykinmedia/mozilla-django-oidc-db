from typing import Any, ClassVar, Generic, TypeVar, cast

from django.http import HttpRequest

from mozilla_django_oidc.middleware import SessionRefresh as BaseSessionRefresh
from typing_extensions import override

from .config import dynamic_setting, get_setting_from_config
from .models import OpenIDConnectConfig, OpenIDConnectConfigBase

T = TypeVar("T", bound=OpenIDConnectConfigBase)


class BaseRefreshMiddleware(Generic[T], BaseSessionRefresh):
    """
    Point the middleware to a particular config class to use.

    This base class sets up the dynamic settings mechanism.
    """

    _config: T
    config_class: ClassVar[type[OpenIDConnectConfigBase]]
    """
    The config model/class to get the endpoints/credentials from.
    """

    OIDC_EXEMPT_URLS = dynamic_setting[list[str]](default=[])
    OIDC_OP_AUTHORIZATION_ENDPOINT = dynamic_setting[str]()
    OIDC_RP_CLIENT_ID = dynamic_setting[str]()
    OIDC_STATE_SIZE = dynamic_setting[int](default=32)
    OIDC_AUTHENTICATION_CALLBACK_URL = dynamic_setting[str](
        default="oidc_authentication_callback"
    )
    OIDC_RP_SCOPES = dynamic_setting[str](default="openid email")
    OIDC_USE_NONCE = dynamic_setting[bool](default=True)
    OIDC_NONCE_SIZE = dynamic_setting[int](default=32)

    def __init__(self, get_response):
        # `super().__init__` is not called here, because it calls self.get_setting()
        # The retrieval of these settings is handled via dynamic settings above.
        super(BaseSessionRefresh, self).__init__(get_response=get_response)

    @override
    def get_settings(self, attr: str, *args: Any) -> Any:  # type: ignore
        """
        Look up the request setting from the database config.

        We cache the resolved config instance on the middleware instance for when
        settings are repeatedly looked up. Note however, that we also override the
        __call__ method to delete this cached property, as a middleware instance lives
        for the entire lifecycle of the applicatation, and each request must not look
        at stale cached configuration.
        """
        if (config := getattr(self, "_config", None)) is None:
            # django-solo and type checking is challenging, but a new release is on the
            # way and should fix that :fingers_crossed:
            config = cast(T, self.config_class.get_solo())
            self._config = config
        return get_setting_from_config(config, attr, *args)

    def __call__(self, request: HttpRequest):
        # reset the python-level cache for each request
        if hasattr(self, "_config"):
            del self._config
        return super().__call__(request)

    def process_request(self, request):
        # do nothing if the configuration is not enabled
        if not self.get_settings("ENABLED"):
            return None
        return super().process_request(request)


class SessionRefresh(BaseRefreshMiddleware[OpenIDConnectConfig]):
    config_class = OpenIDConnectConfig
