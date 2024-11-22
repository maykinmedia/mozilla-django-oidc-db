from django_setup_configuration.configuration import BaseConfigurationStep
from django_setup_configuration.exceptions import ConfigurationRunFailed

from mozilla_django_oidc_db.forms import OIDCSetupConfigForm
from mozilla_django_oidc_db.models import OpenIDConnectConfig
from mozilla_django_oidc_db.setup_configuration.models import (
    AdminOIDCConfigurationModel,
)
from mozilla_django_oidc_db.utils import create_missing_groups


class AdminOIDCConfigurationStep(BaseConfigurationStep[AdminOIDCConfigurationModel]):
    """
    Configure admin login via OpenID Connect
    """

    verbose_name = "Configuration for admin login via OpenID Connect"
    config_model = AdminOIDCConfigurationModel
    namespace = "OIDC_DB_SETUP_CONFIG_ADMIN_AUTH"
    enable_setting = "OIDC_DB_CONFIG_ENABLE"

    def execute(self, model: AdminOIDCConfigurationModel) -> None:

        config = OpenIDConnectConfig.get_solo()

        base_model_data = model.model_dump()
        endpoint_config_data = base_model_data.pop("endpoint_config")

        all_settings = {
            "sync_groups": config.sync_groups,
            "oidc_use_nonce": config.oidc_use_nonce,
            "enabled": True,
            "claim_mapping": config.claim_mapping,  # JSONFormField widget cannot handle blank values with object schema
            "sync_groups_glob_pattern": config.sync_groups_glob_pattern,
            **base_model_data,
            **endpoint_config_data,
        }

        if groups := all_settings.get("default_groups"):
            all_settings["default_groups"] = create_missing_groups(
                groups, all_settings["sync_groups_glob_pattern"]
            )

        form = OIDCSetupConfigForm(
            instance=config,
            data=all_settings,
        )
        if not form.is_valid():
            raise ConfigurationRunFailed(
                "Admin OIDC configuration field validation failed",
                form.errors.as_json(),
            )
        form.save()
