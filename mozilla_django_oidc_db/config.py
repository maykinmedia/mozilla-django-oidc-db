"""
Helpers to work with (dynamic) OIDC configuration.

The utilities here make it easier to work with configuration that lives on a
configuration model instance rather than in Django settings, while also handling
settings that are still defined in the django settings layer.
"""

from typing import Any, Generic, Protocol, TypeVar, overload

from django.apps import apps
from django.core.exceptions import BadRequest
from django.http import HttpRequest

from mozilla_django_oidc.utils import import_from_settings
from typing_extensions import Self, TypedDict, Unpack

from .constants import CONFIG_CLASS_SESSION_KEY
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


T = TypeVar("T")


class SettingsHolder(Protocol[T]):
    def get_settings(self, attr: str, *args: T) -> T: ...


class DynamicSettingKwargs(TypedDict, Generic[T], total=False):
    default: T


class dynamic_setting(Generic[T]):
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
    # Attempt to retrieve the config_class from the session, this only works for users
    # that are actually logged in as Django users
    # The config_class key is added to the state in the OIDCInit.get method.
    # TODO: verify that the state query param is present for error flows! Need to check
    # the OAUTH2 spec for this, but according to ChatGeePeeTee if the request contains
    # it, the callback must have it too.
    config_class = ""
    state_key = request.GET.get("state")
    if state_key and state_key in (states := request.session.get("oidc_states", [])):
        state = states[state_key]
        config_class = state.get("config_class", "")

    if not config_class and (
        _config := request.session.get(CONFIG_CLASS_SESSION_KEY, "")
    ):
        config_class = _config

    try:
        config = apps.get_model(config_class)
    except (LookupError, ValueError) as exc:
        raise BadRequest("Could not look up the referenced config.") from exc

    # Spoofing is not possible since we store it in the server-side session, but there
    # can still be all sorts of programmer mistakes.
    if not issubclass(config, OpenIDConnectConfigBase):
        raise BadRequest("Invalid config referenced.")

    request._oidcdb_config_class = config  # type: ignore


def lookup_config(request: HttpRequest) -> type[OpenIDConnectConfigBase]:
    # cache on request for optimized access
    if (config := getattr(request, "_oidcdb_config_class", None)) is None:
        raise BadRequest("The required config is not available on the request.")
    return config
