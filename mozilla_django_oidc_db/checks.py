import inspect
from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.conf import settings
from django.core.checks import CheckMessage, Error, Warning, register
from django.utils.module_loading import import_string

from .views import OIDCAuthenticationRequestInitView, OIDCCallbackView


def _do_check(
    app_configs: Sequence[AppConfig] | None,
    dotted_path: Any,
    type_error: Error,
    subclass_reference: type,
    subclass_warning: Warning,
) -> list[CheckMessage]:
    if not (
        app_configs is None
        or any(config.name == "mozilla_django_oidc_db" for config in app_configs)
    ):
        return []

    if not isinstance(dotted_path, str):
        return [type_error]

    view_cls = import_string(dotted_path)
    if not inspect.isclass(view_cls) or not issubclass(view_cls, subclass_reference):
        return [subclass_warning]

    return []


@register()
def check_authenticate_class(
    *, app_configs: Sequence[AppConfig] | None, **kwargs
) -> list[CheckMessage]:
    type_error = Error(
        "'settings.OIDC_AUTHENTICATE_CLASS' must be a string that can be imported.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestView' or a "
            "subclass of 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView'."
        ),
        id="mozilla_django_oidc_db.E001",
    )
    subclass_warning = Warning(
        "'settings.OIDC_AUTHENTICATE_CLASS' should be a subclass of 'OIDCAuthenticationRequestInitView'.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestView' or a "
            "subclass of 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView'."
        ),
        id="mozilla_django_oidc_db.W001",
    )

    return _do_check(
        app_configs,
        settings.OIDC_AUTHENTICATE_CLASS,
        type_error=type_error,
        subclass_reference=OIDCAuthenticationRequestInitView,
        subclass_warning=subclass_warning,
    )


@register()
def check_callback_class(
    *, app_configs: Sequence[AppConfig] | None, **kwargs
) -> list[CheckMessage]:
    type_error = Error(
        "'settings.OIDC_CALLBACK_CLASS' must be a string that can be imported.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCCallbackView' or a subclass of it."
        ),
        id="mozilla_django_oidc_db.E002",
    )
    subclass_warning = Warning(
        "'settings.OIDC_CALLBACK_CLASS' should be a subclass of 'OIDCInit'.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCCallbackView' or a subclass of it."
        ),
        id="mozilla_django_oidc_db.W002",
    )

    return _do_check(
        app_configs,
        settings.OIDC_CALLBACK_CLASS,
        type_error=type_error,
        subclass_reference=OIDCCallbackView,
        subclass_warning=subclass_warning,
    )
