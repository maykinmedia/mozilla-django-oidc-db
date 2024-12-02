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
    Configure admin login via OpenID Connect
    """

    verbose_name = "Configuration for admin login via OpenID Connect"
    config_model = AdminOIDCConfigurationModel
    namespace = "oidc_db_config_admin_auth"
    enable_setting = "oidc_db_config_enable"

    def execute(self, model: AdminOIDCConfigurationModel) -> None:

        all_settings = {
            "enabled": model.enabled,
            "oidc_rp_client_id": model.oidc_rp_client_id,
            "oidc_rp_client_secret": model.oidc_rp_client_secret,
            "oidc_rp_sign_algo": model.oidc_rp_sign_algo,
            "oidc_rp_scopes_list": model.oidc_rp_scopes_list,
            "oidc_op_jwks_endpoint": model.oidc_op_jwks_endpoint,
            "oidc_token_use_basic_auth": model.oidc_token_use_basic_auth,
            "oidc_rp_idp_sign_key": model.oidc_rp_idp_sign_key,
            "oidc_op_logout_endpoint": model.oidc_op_logout_endpoint,
            "oidc_use_nonce": model.oidc_use_nonce,
            "oidc_nonce_size": model.oidc_nonce_size,
            "oidc_state_size": model.oidc_state_size,
            "oidc_keycloak_idp_hint": model.oidc_keycloak_idp_hint,
            "userinfo_claims_source": model.userinfo_claims_source,
            "username_claim": model.username_claim,
            "claim_mapping": model.claim_mapping,
            "groups_claim": model.groups_claim,
            "sync_groups": model.sync_groups,
            "sync_groups_glob_pattern": model.sync_groups_glob_pattern,
            "make_users_staff": model.make_users_staff,
            "superuser_group_names": model.superuser_group_names,
            "default_groups": get_groups_by_name(
                model.default_groups, model.sync_groups_glob_pattern, model.sync_groups
            ),
        }

        if isinstance(model.endpoint_config, OIDCDiscoveryEndpoint):
            all_settings.update(
                oidc_op_discovery_endpoint=model.endpoint_config.oidc_op_discovery_endpoint,
            )
        else:
            all_settings.update(
                oidc_op_authorization_endpoint=model.endpoint_config.oidc_op_authorization_endpoint,
                oidc_op_token_endpoint=model.endpoint_config.oidc_op_token_endpoint,
                oidc_op_user_endpoint=model.endpoint_config.oidc_op_user_endpoint,
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
