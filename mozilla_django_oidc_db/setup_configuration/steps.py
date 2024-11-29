from django_setup_configuration.configuration import BaseConfigurationStep
from django_setup_configuration.exceptions import ConfigurationRunFailed

from mozilla_django_oidc_db.forms import OpenIDConnectConfigForm
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
    namespace = "oidc_db_config_admin_auth"
    enable_setting = "oidc_db_config_enable"

    def execute(self, model: AdminOIDCConfigurationModel) -> None:

        config = OpenIDConnectConfig.get_solo()

        all_settings = model.model_dump()
        endpoint_config_data = all_settings.pop("endpoint_config")
        all_settings.update(endpoint_config_data)

        if groups := all_settings.get("default_groups"):
            all_settings["default_groups"] = create_missing_groups(
                groups, all_settings["sync_groups_glob_pattern"]
            )

        form = OpenIDConnectConfigForm(
            instance=config,
            data=all_settings,
        )
        if not form.is_valid():
            raise ConfigurationRunFailed(
                "Admin OIDC configuration field validation failed",
                form.errors.as_json(),
            )
        form.save()
