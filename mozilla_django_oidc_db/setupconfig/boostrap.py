from django.conf import settings
from django.contrib.auth.models import Group

from django_setup_configuration.configuration import BaseConfigurationStep
from django_setup_configuration.exceptions import ConfigurationRunFailed

from ..forms import OpenIDConnectConfigForm
from ..models import OpenIDConnectConfig


class AdminOIDCConfigurationStep(BaseConfigurationStep):
    """
    Configure admin login via OpenID Connect
    """

    verbose_name = "Configuration for admin login via OpenID Connect"
    required_settings = [
        "ADMIN_OIDC_OIDC_RP_CLIENT_ID",
        "ADMIN_OIDC_OIDC_RP_CLIENT_SECRET",
    ]
    all_settings = required_settings + [
        "ADMIN_OIDC_OIDC_RP_SCOPES_LIST",
        "ADMIN_OIDC_OIDC_RP_SIGN_ALGO",
        "ADMIN_OIDC_OIDC_RP_IDP_SIGN_KEY",
        "ADMIN_OIDC_OIDC_OP_DISCOVERY_ENDPOINT",
        "ADMIN_OIDC_OIDC_OP_JWKS_ENDPOINT",
        "ADMIN_OIDC_OIDC_OP_AUTHORIZATION_ENDPOINT",
        "ADMIN_OIDC_OIDC_OP_TOKEN_ENDPOINT",
        "ADMIN_OIDC_OIDC_OP_USER_ENDPOINT",
        "ADMIN_OIDC_USERNAME_CLAIM",
        "ADMIN_OIDC_GROUPS_CLAIM",
        "ADMIN_OIDC_CLAIM_MAPPING",
        "ADMIN_OIDC_SYNC_GROUPS",
        "ADMIN_OIDC_SYNC_GROUPS_GLOB_PATTERN",
        "ADMIN_OIDC_DEFAULT_GROUPS",
        "ADMIN_OIDC_MAKE_USERS_STAFF",
        "ADMIN_OIDC_SUPERUSER_GROUP_NAMES",
        "ADMIN_OIDC_OIDC_USE_NONCE",
        "ADMIN_OIDC_OIDC_NONCE_SIZE",
        "ADMIN_OIDC_OIDC_STATE_SIZE",
        "ADMIN_OIDC_OIDC_EXEMPT_URLS",
        "ADMIN_OIDC_USERINFO_CLAIMS_SOURCE",
    ]
    enable_setting = "ADMIN_OIDC_CONFIG_ENABLE"

    def is_configured(self) -> bool:
        return OpenIDConnectConfig.get_solo().enabled

    def configure(self):
        config = OpenIDConnectConfig.get_solo()

        # Use the model defaults
        form_data = {
            field.name: getattr(config, field.name)
            for field in OpenIDConnectConfig._meta.fields
        }

        # `email` is in the claim_mapping by default, but email is used as the username field
        # by OIP, and you cannot map the username field when using OIDC
        if "email" in form_data["claim_mapping"]:
            del form_data["claim_mapping"]["email"]

        # Only override field values with settings if they are defined
        for setting in self.all_settings:
            value = getattr(settings, setting, None)
            if value is not None:
                model_field_name = setting.split("ADMIN_OIDC_")[1].lower()
                if model_field_name == "default_groups":
                    for group_name in value:
                        Group.objects.get_or_create(name=group_name)
                    value = Group.objects.filter(name__in=value)

                form_data[model_field_name] = value
        form_data["enabled"] = True

        # Use the admin form to apply validation and fetch URLs from the discovery endpoint
        form = OpenIDConnectConfigForm(data=form_data)
        if not form.is_valid():
            raise ConfigurationRunFailed(
                f"Something went wrong while saving configuration: {form.errors.as_json()}"
            )

        form.save()

    def test_configuration(self):
        """
        TODO not sure if it is feasible (because there are different possible IdPs),
        but it would be nice if we could test the login automatically
        """
