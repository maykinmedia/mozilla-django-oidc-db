from django.http import HttpRequest, HttpResponseBase

from mozilla_django_oidc_db.plugins import OIDCAdminPlugin
from mozilla_django_oidc_db.registry import register
from mozilla_django_oidc_db.views import AdminCallbackView

from .views import CustomCallbackView

callback_view = AdminCallbackView.as_view()


class TestPlugin(OIDCAdminPlugin):
    def handle_callback(self, request: HttpRequest) -> HttpResponseBase:
        return callback_view(request)


@register("test-oidc")
class OIDCTestPlugin(TestPlugin):
    def validate_settings(self) -> None:
        pass

    def get_schema(self):
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Options",
            "description": "OIDC Configuration options.",
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "custom-option-key": {
                    "description": "A custom property",
                    "type": "string",
                }
            },
        }


@register("test-oidc-not-configured")
class OIDCTestNotConfiguredPlugin(TestPlugin):
    pass


@register("test-oidc-another-not-configured")
class OIDCTestAnotherNotConfiguredPlugin(TestPlugin):
    pass


@register("test-oidc-disabled")
class OIDCTestDisabledPlugin(TestPlugin):
    pass


@register("test-keycloak")
class OIDCTestKeycloakPlugin(TestPlugin):
    pass


@register("test-keycloak-custom")
class OIDCTestKeycloakCustomPlugin(OIDCAdminPlugin):
    def handle_callback(self, request: HttpRequest) -> HttpResponseBase:
        callback_view = CustomCallbackView.as_view()
        return callback_view(request)
