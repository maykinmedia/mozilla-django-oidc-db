from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path

from mozilla_django_oidc_db.views import (
    AdminLoginFailure,
    OIDCAuthenticationRequestView,
)

from .views import (
    another_empty_config_callback_view_init,
    custom_callback_view_init,
    empty_config_callback_view_init,
)

urlpatterns = [
    path("admin/login/failure/", AdminLoginFailure.as_view(), name="admin-oidc-error"),
    path("admin/", admin.site.urls),
    path("login", OIDCAuthenticationRequestView.as_view(), name="login"),
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("custom-init-login/", custom_callback_view_init, name="custom-init-login"),
    # In most cases, consumers will use the generic callback handler that dynmically
    # resolves to the appropriate view handler, depending on the config information
    # in the request. These additional URLs are there to mimic the situation in which
    # consumers do actually implement different endpoints for different OIDC handlers,
    # even though this is not the recommended approach.
    path(
        "empty-config-callback/",
        empty_config_callback_view_init,
        name="empty-config-callback",
    ),
    path(
        "another-empty-config-callback/",
        another_empty_config_callback_view_init,
        name="another-empty-config-callback",
    ),
] + staticfiles_urlpatterns()
