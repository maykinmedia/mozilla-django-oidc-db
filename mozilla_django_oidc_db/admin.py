from django.contrib import admin
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from .forms import OIDCProviderForm
from .models import OIDCClient, OIDCProvider


@admin.register(OIDCClient)
class OIDCClientAdmin(admin.ModelAdmin):
    list_display = (
        "identifier",
        "oidc_rp_client_id",
        "enabled",
    )
    search_fields = ("identifier", "oidc_provider__identifier", "oidc_rp_client_id")
    fieldsets = (
        (
            _("Activation"),
            {"fields": ("enabled",)},
        ),
        (
            _("OIDC Provider"),
            {"fields": ("oidc_provider", "check_op_availability")},
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
        self, request: HttpRequest, obj: OIDCClient | None = None
    ) -> bool:
        return False

    def get_form(self, request, obj=None, change=False, **kwargs):
        form = super().get_form(request, obj, change, **kwargs)

        # The JSON schema for the `options` field needs to be deduced from the instance.
        # django_jsonform field passes the instance to the callable to get the schema
        # if the attribute `instance` is present on the widget instance
        form.base_fields["options"].widget.instance = obj

        return form


@admin.register(OIDCProvider)
class OIDCProviderAdmin(admin.ModelAdmin):
    list_display = ("identifier",)
    search_fields = ("identifier",)
    form = OIDCProviderForm
