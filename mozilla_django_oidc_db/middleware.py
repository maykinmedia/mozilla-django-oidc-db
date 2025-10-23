from typing import Any, override

from django.urls import reverse

from mozilla_django_oidc.middleware import SessionRefresh as BaseSessionRefresh

from .config import (
    BadRequest,
    dynamic_setting,
    get_setting_from_config,
    lookup_config,
)
from .models import OIDCClient


class SessionRefresh(BaseSessionRefresh):
    """
    Refresh stale sessions based on a config dynamically resolved from the session.
    """

    _config: OIDCClient

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
            raise BadRequest("No config object was set from the request")

        return get_setting_from_config(config, attr, *args)

    def _set_config_from_request(self, request):
        self._config = lookup_config(request)

    def process_request(self, request):
        try:
            self._set_config_from_request(request)
        except BadRequest:
            return None

        # do nothing if the configuration is not enabled
        if not self.get_settings("ENABLED"):
            return None

        return super().process_request(request)

    # we can't use cached_property, because a middleware instance exists for the whole
    # duration of the django server life cycle, and the relevant config can change
    # between requests. See ``process_request``.
    @property
    def exempt_urls(self):  # pyright: ignore[reportIncompatibleVariableOverride]
        # In many cases, the OIDC_AUTHENTICATION_CALLBACK_URL will be the generic
        # callback handler and already be part of super().exempt_urls. However, this is
        # not a given, and consumers might have implemented different callback handlers,
        # in which case they may have overridden the callback URL on the config class.
        #
        # If this is the case, it should always be part of the exempt URLs.
        callback_url = self.OIDC_AUTHENTICATION_CALLBACK_URL
        return {
            callback_url if callback_url.startswith("/") else reverse(callback_url)
        } | super().exempt_urls
