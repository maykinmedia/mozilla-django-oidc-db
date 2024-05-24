from mozilla_django_oidc_db.views import OIDCAuthenticationCallbackView, OIDCInit

from .models import CustomCallbackViewConfig


class CustomCallbackView(OIDCAuthenticationCallbackView):
    @property
    def success_url(self):
        return "/custom-success-url"


custom_callback_view_init = OIDCInit.as_view(config_class=CustomCallbackViewConfig)
