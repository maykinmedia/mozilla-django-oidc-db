from mozilla_django_oidc_db.views import (
    AdminCallbackView,
    OIDCAuthenticationRequestInitView,
)


class PreConfiguredOIDCAuthenticationRequestView(OIDCAuthenticationRequestInitView):
    identifier = "test-oidc"


class CustomCallbackView(AdminCallbackView):
    success_url = "/custom-success-url"
