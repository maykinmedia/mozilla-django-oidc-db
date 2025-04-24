from django.contrib import admin
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from .forms import OIDCProviderConfigForm
from .models import OIDCConfig, OIDCProviderConfig


@admin.register(OIDCConfig)
class OIDCConfigAdmin(admin.ModelAdmin):
    list_display = (
        "identifier",
        "enabled",
    )
    list_filter = ("identifier", "oidc_provider_config__identifier")
    fieldsets = (
        (
            _("Activation"),
            {"fields": ("enabled",)},
        ),
        (
            _("OIDC Provider"),
            {"fields": ("oidc_provider_config", "check_op_availability")},
        ),
        (
            _("Relying Party settings"),
            {
                "fields": (
                    "oidc_rp_client_id",
                    "oidc_rp_client_secret",
                    "oidc_rp_scopes_list",
                    "oidc_rp_sign_algo",
                    "oidc_rp_idp_sign_key",
                )
            },
        ),
        (_("Custom settings"), {"fields": ("options",)}),
        (
            _("Advanced settings"),
            {
                "fields": (
                    "oidc_use_nonce",
                    "oidc_nonce_size",
                    "oidc_state_size",
                    "userinfo_claims_source",
                    "oidc_keycloak_idp_hint",
                ),
                "classes": [
                    "collapse in",
                ],
            },
        ),
    )

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(
        self, request: HttpRequest, obj: OIDCConfig = None
    ) -> bool:
        return False


@admin.register(OIDCProviderConfig)
class OIDCProviderConfigAdmin(admin.ModelAdmin):
    list_display = ("identifier",)
    list_filter = ("identifier",)
    form = OIDCProviderConfigForm
