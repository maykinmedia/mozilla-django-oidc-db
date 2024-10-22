from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory
from django.utils.translation import gettext as _

from django_setup_configuration.config_settings import ConfigSettings
from django_setup_configuration.configuration import BaseConfigurationStep
from django_setup_configuration.exceptions import ConfigurationRunFailed, SelfTestFailed

from .forms import OIDCSetupConfigForm
from .models import OpenIDConnectConfig
from .views import OIDCAuthenticationRequestView


class AdminOIDCConfigurationStep(BaseConfigurationStep):
    """
    Configure admin login via OpenID Connect
    """

    verbose_name = _("Configuration for admin login via OpenID Connect")

    config_settings = ConfigSettings(
        enable_setting="OIDC_DB_CONFIG_ENABLE",
        display_name=_("Admin OIDC Configuration"),
        namespace="OIDC_DB",
        models=[OpenIDConnectConfig],
        update_fields=True,
        required_settings=["OIDC_DB_SETUP_CONFIG_ADMIN_AUTH"],
    )

    def is_configured(self) -> bool:
        return OpenIDConnectConfig.get_solo().enabled

    def configure(self):
        config = OpenIDConnectConfig.get_solo()

        all_settings = {
            "sync_groups": config.sync_groups,
            "oidc_use_nonce": config.oidc_use_nonce,
            "enabled": True,
            **settings.OIDC_DB_SETUP_CONFIG_ADMIN_AUTH,
        }

        if groups := all_settings.get("default_groups"):
            for group_name in groups:
                Group.objects.get_or_create(name=group_name)
            all_settings["default_groups"] = Group.objects.filter(name__in=groups)

        form = OIDCSetupConfigForm(
            instance=config,
            data=all_settings,
        )
        if not form.is_valid():
            raise ConfigurationRunFailed(
                f"Something went wrong while saving configuration: {form.errors.as_json()}"
            )

        form.save()

    def test_configuration(self):

        request_factory = RequestFactory()
        request = request_factory.get("/irrelevant")

        middleware = SessionMiddleware(lambda x: None)  # type: ignore
        middleware.process_request(request)
        request.session.save()

        response = OIDCAuthenticationRequestView.as_view()(request)

        if response.status_code != 302:
            raise SelfTestFailed

        config = OpenIDConnectConfig.get_solo()

        if not response.url.startswith(config.oidc_op_authorization_endpoint):
            raise SelfTestFailed
