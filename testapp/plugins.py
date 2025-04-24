from mozilla_django_oidc_db.plugins import OIDCAdminPlugin
from mozilla_django_oidc_db.registry import register
from mozilla_django_oidc_db.views import AdminCallbackView

from .views import CustomCallbackView


@register("test-oidc")
class OIDCTestPlugin(OIDCAdminPlugin):
    callback_view = AdminCallbackView

    def validate_settings(self) -> None:
        pass


@register("test-oidc-not-configured")
class OIDCTestNotConfiguredPlugin(OIDCAdminPlugin):
    callback_view = AdminCallbackView


@register("test-oidc-another-not-configured")
class OIDCTestNotConfiguredPlugin(OIDCAdminPlugin):
    callback_view = AdminCallbackView


@register("test-oidc-disabled")
class OIDCTestDisabledPlugin(OIDCAdminPlugin):
    callback_view = AdminCallbackView


@register("test-keycloak")
class OIDCTestKeycloakPlugin(OIDCAdminPlugin):
    callback_view = AdminCallbackView


@register("test-keycloak-custom")
class OIDCTestKeycloakPlugin(OIDCAdminPlugin):
    callback_view = CustomCallbackView
