from django.apps import apps
from django.core.checks import Error, Warning

import pytest

from mozilla_django_oidc_db.checks import check_authenticate_class, check_callback_class


@pytest.fixture(scope="session")
def app_configs():
    app_config = apps.get_app_config(app_label="mozilla_django_oidc_db")
    return [app_config]


def test_nothing_reported_when_checking_other_app_label(settings):
    settings.OIDC_AUTHENTICATE_CLASS = object()  # this is invalid
    app_config = apps.get_app_config(app_label="admin")

    messages = check_authenticate_class(app_configs=[app_config])

    assert len(messages) == 0


def test_check_authenticate_class_ok(app_configs, settings):
    settings.OIDC_AUTHENTICATE_CLASS = (
        "mozilla_django_oidc_db.views.OIDCAuthenticationRequestView"
    )

    messages = check_authenticate_class(app_configs=app_configs)

    assert len(messages) == 0


def test_check_authenticate_class_not_a_string(app_configs, settings):
    settings.OIDC_AUTHENTICATE_CLASS = object()

    messages = check_authenticate_class(app_configs=app_configs)

    assert len(messages) == 1
    assert messages[0] == Error(
        "'settings.OIDC_AUTHENTICATE_CLASS' must be a string that can be imported.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestView' or a "
            "subclass of 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView'."
        ),
        id="mozilla_django_oidc_db.E001",
    )


def test_check_authenticate_class_invalid_view(app_configs, settings):
    settings.OIDC_AUTHENTICATE_CLASS = "django.views.View"

    messages = check_authenticate_class(app_configs=app_configs)

    assert len(messages) == 1
    assert messages[0] == Warning(
        "'settings.OIDC_AUTHENTICATE_CLASS' should be a subclass of 'OIDCAuthenticationRequestInitView'.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestView' or a "
            "subclass of 'mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView'."
        ),
        id="mozilla_django_oidc_db.W001",
    )


def test_check_callback_class_ok(app_configs, settings):
    settings.OIDC_CALLBACK_CLASS = "mozilla_django_oidc_db.views.OIDCCallbackView"

    messages = check_callback_class(app_configs=app_configs)

    assert len(messages) == 0


def test_check_callback_class_not_a_string(app_configs, settings):
    settings.OIDC_CALLBACK_CLASS = object()

    messages = check_callback_class(app_configs=app_configs)

    assert len(messages) == 1
    assert messages[0] == Error(
        "'settings.OIDC_CALLBACK_CLASS' must be a string that can be imported.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCCallbackView' or a subclass of it."
        ),
        id="mozilla_django_oidc_db.E002",
    )


def test_check_callback_class_invalid_view(app_configs, settings):
    settings.OIDC_CALLBACK_CLASS = "django.views.View"

    messages = check_callback_class(app_configs=app_configs)

    assert len(messages) == 1
    assert messages[0] == Warning(
        "'settings.OIDC_CALLBACK_CLASS' should be a subclass of 'OIDCInit'.",
        hint=(
            "Use 'mozilla_django_oidc_db.views.OIDCCallbackView' or a subclass of it."
        ),
        id="mozilla_django_oidc_db.W002",
    )
