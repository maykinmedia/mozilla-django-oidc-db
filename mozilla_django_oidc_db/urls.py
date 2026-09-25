"""
URL patterns for the mozilla-django-oidc-db account-merge onboarding flow.

Include these in your project's URL conf alongside the OIDC callback URL::

    from django.urls import include, path

    urlpatterns = [
        # ... other urls ...
        path("oidc/", include("mozilla_django_oidc.urls")),
        path("oidc/", include("mozilla_django_oidc_db.urls")),
    ]

The admin-specific URL (``admin-oidc-account-merge``) is referenced by
:class:`~mozilla_django_oidc_db.views.AdminCallbackView`; the generic URL
(``oidc-account-merge``) is used by
:class:`~mozilla_django_oidc_db.views.OIDCAuthenticationCallbackView`.
"""

from django.urls import path

from .views import AdminAccountMergeView, OIDCAccountMergeView

urlpatterns = [
    path(
        "account-merge/",
        OIDCAccountMergeView.as_view(),
        name="oidc-account-merge",
    ),
    path(
        "admin/account-merge/",
        AdminAccountMergeView.as_view(),
        name="admin-oidc-account-merge",
    ),
]
