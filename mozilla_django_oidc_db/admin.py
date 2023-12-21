from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from solo.admin import SingletonModelAdmin

from .forms import OpenIDConnectConfigForm
from .models import OpenIDConnectConfig


@admin.register(OpenIDConnectConfig)
class OpenIDConnectConfigAdmin(DynamicArrayMixin, SingletonModelAdmin):
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
                    "oidc_op_user_endpoint",
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
            _("Advanced settings"),
            {
                "fields": (
                    "oidc_use_nonce",
                    "oidc_nonce_size",
                    "oidc_state_size",
                    "oidc_exempt_urls",
                    "userinfo_claims_source",
                ),
                "classes": [
                    "collapse in",
                ],
            },
        ),
    )
    filter_horizontal = ("default_groups",)
