from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from solo.admin import SingletonModelAdmin

from .forms import OpenIDConnectConfigForm
from .models import OIDCConfig, OIDCProviderConfig, OpenIDConnectConfig


@admin.register(OpenIDConnectConfig)
class OpenIDConnectConfigAdmin(SingletonModelAdmin):
    form = OpenIDConnectConfigForm
    fieldsets = (
        (
            _("Activation"),
            {"fields": ("enabled",)},
        ),
        (
            _("Common settings"),
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
        (
            _("Endpoints"),
            {
                "fields": (
                    "oidc_op_discovery_endpoint",
                    "oidc_op_jwks_endpoint",
                    "oidc_op_authorization_endpoint",
                    "oidc_op_token_endpoint",
                    "oidc_token_use_basic_auth",
                    "oidc_op_user_endpoint",
                    "oidc_op_logout_endpoint",
                )
            },
        ),
        (
            _("User profile"),
            {
                "fields": (
                    "username_claim",
                    "groups_claim",
                    "claim_mapping",
                    "sync_groups",
                    "sync_groups_glob_pattern",
                    "default_groups",
                    "make_users_staff",
                    "superuser_group_names",
                )
            },
        ),
        (
            _("Keycloak specific settings"),
            {
                "fields": ("oidc_keycloak_idp_hint",),
                "classes": ["collapse in"],
            },
        ),
        (
            _("Advanced settings"),
            {
                "fields": (
                    "oidc_use_nonce",
                    "oidc_nonce_size",
                    "oidc_state_size",
                    "userinfo_claims_source",
                ),
                "classes": [
                    "collapse in",
                ],
            },
        ),
    )
    filter_horizontal = ("default_groups",)


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
            {"fields": ("oidc_provider_config",)},
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


@admin.register(OIDCProviderConfig)
class OIDCProviderConfigAdmin(admin.ModelAdmin):
    list_display = ("identifier",)
    list_filter = ("identifier",)
