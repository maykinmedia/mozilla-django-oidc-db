from django.http import HttpResponse

from mozilla_django_oidc_db.views import (
    OIDCAuthenticationCallbackView,
    OIDCInit,
)

from .models import AnotherEmptyConfig, CustomCallbackViewConfig, EmptyConfig


class CustomCallbackView(OIDCAuthenticationCallbackView):
    @property
    def success_url(self):
        return "/custom-success-url"


custom_callback_view_init = OIDCInit.as_view(config_class=CustomCallbackViewConfig)
empty_config_callback_view_init = lambda r: HttpResponse()
another_empty_config_callback_view_init = lambda r: HttpResponse()
