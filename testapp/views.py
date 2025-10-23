from mozilla_django_oidc_db.views import (
    AdminCallbackView,
    OIDCAuthenticationRequestInitView,
)


class PreConfiguredOIDCAuthenticationRequestView(OIDCAuthenticationRequestInitView):
    identifier = "test-oidc"


class CustomCallbackView(AdminCallbackView):
    @property
    def success_url(self):
        return "/custom-success-url"
