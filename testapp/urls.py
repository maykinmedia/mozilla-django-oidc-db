from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path

from mozilla_django_oidc_db.views import (
    AdminLoginFailure,
    OIDCAuthenticationRequestInitView,
)

from .views import PreConfiguredOIDCAuthenticationRequestView

urlpatterns = [
    path("admin/login/failure/", AdminLoginFailure.as_view(), name="admin-oidc-error"),
    path("admin/", admin.site.urls),
    path("login", PreConfiguredOIDCAuthenticationRequestView.as_view(), name="login"),
    path(
        "login/keycloak",
        OIDCAuthenticationRequestInitView.as_view(identifier="test-keycloak"),
        name="login-keycloak",
    ),
    path(
        "login/keycloak-custom",
        OIDCAuthenticationRequestInitView.as_view(
            identifier="test-keycloak-custom",
        ),
        name="login-keycloak-custom",
    ),
    path("oidc/", include("mozilla_django_oidc.urls")),
] + staticfiles_urlpatterns()
