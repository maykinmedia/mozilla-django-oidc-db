"""
Helpers to work with (dynamic) OIDC configuration.

The utilities here make it easier to work with configuration that lives on a
configuration model instance rather than in Django settings, while also handling
settings that are still defined in the django settings layer.
"""

from typing import Any, Protocol, Self, TypeVar, Unpack, overload

from django.core.exceptions import (
    BadRequest,
)
from django.http import HttpRequest

from mozilla_django_oidc.utils import import_from_settings
from typing_extensions import TypedDict

from .constants import CONFIG_IDENTIFIER_SESSION_KEY
from .models import OIDCClient


def get_setting_from_config(config: OIDCClient, attr: str, *args) -> Any:
    """
    Look up a setting from the config record or fall back to Django settings.

    Django settings are defined as ``OIDC_SOME_SETTING``, in upper case, while our
    model fields typically match the name, but in lower case. So, we look up if the
    requested setting exists as an attribute on the configuration instance and use that
    when provided, otherwise we fall back to the django settings module.

    .. note:: A setting may also be defined as a (calculated) property of some kind on
       a/the configuration instance, rather than an explicit model field. That's why
       we use ``hasattr`` checks rather than relying on
       ``config._meta.get_field(some_field)``.
    """
    attr_lowercase = attr.lower()

    if attr_lowercase == "oidc_op_auth_endpoint":
        assert config.oidc_provider
        return config.oidc_provider.oidc_op_authorization_endpoint

    if attr_lowercase.startswith("oidc_op") and hasattr(
        config.oidc_provider, attr_lowercase
    ):
        return getattr(config.oidc_provider, attr_lowercase)

    if attr_lowercase in [
        "oidc_token_use_basic_auth",
        "oidc_use_nonce",
        "oidc_nonce_size",
        "oidc_state_size",
    ]:
        return getattr(config.oidc_provider, attr_lowercase)

    if hasattr(config, attr_lowercase):
        # Workaround for OIDC_RP_IDP_SIGN_KEY being an empty string by default.
        # mozilla-django-oidc explicitly checks if `OIDC_RP_IDP_SIGN_KEY` is not `None`
        # https://github.com/mozilla/mozilla-django-oidc/blob/master/mozilla_django_oidc/auth.py#L189
        if (value_from_config := getattr(config, attr_lowercase)) == "":
            return None
        return value_from_config
    return import_from_settings(attr, *args)


T = TypeVar("T")


class SettingsHolder(Protocol[T]):
    def get_settings(self, attr: str, *args: T) -> T: ...


class DynamicSettingKwargs[T](TypedDict, total=False):
    default: T


class dynamic_setting[T]:
    """
    Descriptor to lazily access settings while explicitly defining them.

    The instance/class accessing these properties needs to support the ``get_settings``
    method.

    Example usage:

    .. code-block:: python

        class MyBackend(BaseBackend):
            OIDC_OP_TOKEN_ENDPOINT = dynamic_setting[str]()
    """

    _default_set: bool = False
    default: T

    def __init__(self, **kwargs: Unpack[DynamicSettingKwargs[T]]):
        if (default := kwargs.get("default")) is not None:
            self.default = default
            self._default_set = True

    def __set_name__(self, owner: type[object], name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        default = f" (default: {self.default!r})" if self._default_set else ""
        return f"<dynamic_setting {self.name}{default}>"

    @overload
    def __get__(self, obj: None, objtype: None) -> Self: ...

    @overload
    def __get__(self, obj: SettingsHolder[T], objtype: type[object]) -> T: ...

    def __get__(
        self, obj: SettingsHolder[T] | None, objtype: type[object] | None = None
    ) -> Self | T:
        if obj is None:
            return self
        args = () if not self._default_set else (self.default,)
        return obj.get_settings(self.name, *args)

    def __set__(self, obj: object | None, value: Any) -> None:
        raise AttributeError(f"setting {self.name} is read-only")


def store_config(request: HttpRequest) -> None:
    """
    Store the requested config (class) on the request object.

    mozilla-django-oidc's callback view deletes the state key after it has validated it,
    so our :func:`lookup_config` cannot extract it from the session anymore.
    """
    # Attempt to retrieve the config_identifier from the session, this only works for users
    # that are actually logged in as Django users
    # The config_identifier key is added to the state in the OIDCAuthenticationRequestInitView.get method.
    # The state parameter is present in the error flow if it was present in the Authorization request: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
    config_identifier = ""
    state_key = request.GET.get("state")
    if state_key and state_key in (states := request.session.get("oidc_states", [])):
        state = states[state_key]
        config_identifier = state.get("config_identifier", "")

    if not config_identifier and (
        _config := request.session.get(CONFIG_IDENTIFIER_SESSION_KEY, "")
    ):
        config_identifier = _config

    request._oidcdb_config = OIDCClient.objects.resolve(config_identifier)  # pyright: ignore[reportAttributeAccessIssue]


def lookup_config(request: HttpRequest) -> OIDCClient:
    # cache on request for optimized access -- preferred access
    if config := getattr(request, "_oidcdb_config", None):
        return config

    # if not cached, try to reconstruct from session
    if (session := getattr(request, "session", None)) is None:
        raise BadRequest("No session present on request")

    if (config_identifier := session.get(CONFIG_IDENTIFIER_SESSION_KEY)) is None:
        raise BadRequest("The required config is not available on the session.")

    return OIDCClient.objects.resolve(config_identifier)
