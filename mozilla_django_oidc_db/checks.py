import inspect
from collections.abc import Sequence

from django.apps import AppConfig
from django.conf import settings
from django.core.checks import CheckMessage, Error, Warning, register
from django.utils.module_loading import import_string

from .views import OIDCCallbackView, OIDCInit


@register()
def check_authenticate_class(
    *, app_configs: Sequence[AppConfig] | None, **kwargs
) -> list[CheckMessage]:
    if not (
        app_configs is None
        or any(config.name == "mozilla_django_oidc_db" for config in app_configs)
    ):
        return []

    dotted_path = settings.OIDC_AUTHENTICATE_CLASS
    if not isinstance(dotted_path, str):
        return [
            Error(
                "'settings.OIDC_AUTHENTICATE_CLASS' must be a string that can be imported.",
                hint=(
                    "Use 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestView' or a "
                    "subclass of 'mozilla_django_oidc_db.views.OIDCInit'."
                ),
                id="mozilla_django_oidc_db.E001",
            )
        ]

    view_cls = import_string(dotted_path)
    if not inspect.isclass(view_cls) or not issubclass(view_cls, OIDCInit):
        return [
            Warning(
                "'settings.OIDC_AUTHENTICATE_CLASS' should be a subclass of 'OIDCInit'.",
                hint=(
                    "Use 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestView' or a "
                    "subclass of 'mozilla_django_oidc_db.views.OIDCInit'."
                ),
                id="mozilla_django_oidc_db.W001",
            )
        ]

    return []


@register()
def check_callback_class(
    *, app_configs: Sequence[AppConfig] | None, **kwargs
) -> list[CheckMessage]:
    if not (
        app_configs is None
        or any(config.name == "mozilla_django_oidc_db" for config in app_configs)
    ):
        return []

    dotted_path = settings.OIDC_CALLBACK_CLASS
    if not isinstance(dotted_path, str):
        return [
            Error(
                "'settings.OIDC_CALLBACK_CLASS' must be a string that can be imported.",
                hint=(
                    "Use 'mozilla_django_oidc_db.views.OIDCCallbackView' or a "
                    "subclass of it."
                ),
                id="mozilla_django_oidc_db.E002",
            )
        ]

    view_cls = import_string(dotted_path)
    if not inspect.isclass(view_cls) or not issubclass(view_cls, OIDCCallbackView):
        return [
            Warning(
                "'settings.OIDC_CALLBACK_CLASS' should be a subclass of 'OIDCInit'.",
                hint=(
                    "Use 'mozilla_django_oidc_db.views.OIDCCallbackView' or a "
                    "subclass of it."
                ),
                id="mozilla_django_oidc_db.W002",
            )
        ]

    return []
