from django_setup_configuration.configuration import BaseConfigurationStep
from django_setup_configuration.exceptions import ConfigurationRunFailed

from mozilla_django_oidc_db.forms import OpenIDConnectConfigForm
from mozilla_django_oidc_db.models import OpenIDConnectConfig
from mozilla_django_oidc_db.setup_configuration.models import (
    AdminOIDCConfigurationModel,
    OIDCDiscoveryEndpoint,
)
from mozilla_django_oidc_db.utils import get_groups_by_name


class AdminOIDCConfigurationStep(BaseConfigurationStep[AdminOIDCConfigurationModel]):
    """
    Configure the necessary settings to enable OpenID Connect authentication for admin users.

    This allows admin users to log in with Single Sign On (SSO) to access the management interface.
    """

    verbose_name = "Configuration for admin login via OpenID Connect"
    config_model = AdminOIDCConfigurationModel
    namespace = "oidc_db_config_admin_auth"
    enable_setting = "oidc_db_config_enable"

    def execute(self, model: AdminOIDCConfigurationModel) -> None:
        if len(model.items) != 1:
            raise ConfigurationRunFailed(
                "You must specify exactly one OIDC configuration"
            )

        config_model = model.items[0]

        all_settings = {
            "enabled": config_model.enabled,
            "oidc_rp_client_id": config_model.oidc_rp_client_id,
            "oidc_rp_client_secret": config_model.oidc_rp_client_secret,
            "oidc_rp_sign_algo": config_model.oidc_rp_sign_algo,
            "oidc_rp_scopes_list": config_model.oidc_rp_scopes_list,
            "oidc_token_use_basic_auth": config_model.oidc_token_use_basic_auth,
            "oidc_rp_idp_sign_key": config_model.oidc_rp_idp_sign_key,
            "oidc_use_nonce": config_model.oidc_use_nonce,
            "oidc_nonce_size": config_model.oidc_nonce_size,
            "oidc_state_size": config_model.oidc_state_size,
            "oidc_keycloak_idp_hint": config_model.oidc_keycloak_idp_hint,
            "userinfo_claims_source": config_model.userinfo_claims_source,
            "username_claim": config_model.username_claim,
            "claim_mapping": config_model.claim_mapping,
            "groups_claim": config_model.groups_claim,
            "sync_groups": config_model.sync_groups,
            "sync_groups_glob_pattern": config_model.sync_groups_glob_pattern,
            "make_users_staff": config_model.make_users_staff,
            "superuser_group_names": config_model.superuser_group_names,
            "default_groups": get_groups_by_name(
                config_model.default_groups,
                config_model.sync_groups_glob_pattern,
                config_model.sync_groups,
            ),
        }

        if isinstance(config_model.endpoint_config, OIDCDiscoveryEndpoint):
            all_settings.update(
                oidc_op_discovery_endpoint=config_model.endpoint_config.oidc_op_discovery_endpoint,
            )
        else:
            all_settings.update(
                oidc_op_authorization_endpoint=config_model.endpoint_config.oidc_op_authorization_endpoint,
                oidc_op_token_endpoint=config_model.endpoint_config.oidc_op_token_endpoint,
                oidc_op_user_endpoint=config_model.endpoint_config.oidc_op_user_endpoint,
                oidc_op_logout_endpoint=config_model.endpoint_config.oidc_op_logout_endpoint,
                oidc_op_jwks_endpoint=config_model.endpoint_config.oidc_op_jwks_endpoint,
            )

        form = OpenIDConnectConfigForm(
            instance=OpenIDConnectConfig.get_solo(),
            data=all_settings,
        )
        if not form.is_valid():
            raise ConfigurationRunFailed(
                "Admin OIDC configuration field validation failed",
                form.errors.as_json(),
            )
        form.save()
