import warnings

from django.core.exceptions import ObjectDoesNotExist

from django_setup_configuration.configuration import BaseConfigurationStep
from django_setup_configuration.exceptions import ConfigurationRunFailed

from mozilla_django_oidc_db.forms import OIDCProviderForm
from mozilla_django_oidc_db.models import OIDCClient, OIDCProvider
from mozilla_django_oidc_db.setup_configuration.models import (
    AdminOIDCConfigurationModel,
    AdminOIDCConfigurationModelItem,
    OIDCConfigProviderModel,
    OIDCDiscoveryProviderConfig,
)


# TODO: We now have a single step that supports the yaml files used in versions <= 0.23.0 and >0.23.0.
# When we drop compatibility, this should be refactor to have two steps: one for the provider and
# one for the client models.
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
        # Configure OIDC Providers
        for provider_config_model in model.providers:
            self._create_or_update_providers(provider_config_model)

        for config_model in model.items:
            self._create_or_update_configuration(config_model)

    def _get_endpoints(self, endpoint_config) -> dict:
        endpoints = {}
        if isinstance(endpoint_config, OIDCDiscoveryProviderConfig):
            endpoints.update(
                oidc_op_discovery_endpoint=endpoint_config.oidc_op_discovery_endpoint,
            )
        else:
            endpoints.update(
                oidc_op_authorization_endpoint=endpoint_config.oidc_op_authorization_endpoint,
                oidc_op_token_endpoint=endpoint_config.oidc_op_token_endpoint,
                oidc_op_user_endpoint=endpoint_config.oidc_op_user_endpoint,
                oidc_op_logout_endpoint=endpoint_config.oidc_op_logout_endpoint,
                oidc_op_jwks_endpoint=endpoint_config.oidc_op_jwks_endpoint,
            )
        return endpoints

    def _create_or_update_provider_deprecated(
        self, config_model: AdminOIDCConfigurationModelItem
    ) -> OIDCProvider:
        warnings.warn(
            "Specifying the OIDC Provider settings directly in the OIDC configuration is deprecated. "
            "Provide the settings for the OIDC Provider separately.",
            DeprecationWarning,
            stacklevel=2,
        )

        identifier = f"{config_model.identifier}-provider"
        settings_provider = {
            "identifier": identifier,
            "oidc_token_use_basic_auth": config_model.oidc_token_use_basic_auth,
            "oidc_use_nonce": config_model.oidc_use_nonce,
            "oidc_nonce_size": config_model.oidc_nonce_size,
            "oidc_state_size": config_model.oidc_state_size,
            **self._get_endpoints(config_model.endpoint_config),
        }

        provider, _ = OIDCProvider.objects.update_or_create(identifier=identifier)
        form = OIDCProviderForm(
            instance=provider,
            data=settings_provider,
        )
        if not form.is_valid():
            raise ConfigurationRunFailed(
                "Admin OIDC configuration field validation failed",
                form.errors.as_json(),
            )
        provider = form.save()
        return provider

    def _create_or_update_configuration(
        self, config_model: AdminOIDCConfigurationModelItem
    ) -> None:
        if not config_model.oidc_provider_identifier:
            provider = self._create_or_update_provider_deprecated(config_model)
        else:
            try:
                provider = OIDCProvider.objects.get(
                    identifier=config_model.oidc_provider_identifier
                )
            except ObjectDoesNotExist as exc:
                raise ConfigurationRunFailed(
                    f"Could not find an existing OIDC Provider with "
                    f"identifier `{config_model.oidc_provider_identifier}`."
                ) from exc

        all_settings = {
            "enabled": config_model.enabled,
            "oidc_rp_client_id": config_model.oidc_rp_client_id,
            "oidc_rp_client_secret": config_model.oidc_rp_client_secret,
            "oidc_rp_sign_algo": config_model.oidc_rp_sign_algo,
            "oidc_rp_scopes_list": config_model.oidc_rp_scopes_list,
            "oidc_rp_idp_sign_key": config_model.oidc_rp_idp_sign_key,
            "oidc_keycloak_idp_hint": config_model.oidc_keycloak_idp_hint,
            "userinfo_claims_source": config_model.userinfo_claims_source,
            "oidc_provider": provider,
            "options": {},
        }

        config, _ = OIDCClient.objects.update_or_create(
            identifier=config_model.identifier, defaults=all_settings
        )

        if config_model.options:
            config.options = config_model.options
        else:
            warnings.warn(
                "The OIDC configuration attributes ``username_claim``, ``claim_mapping``, ``sync_groups``, "
                "``sync_groups_glob_pattern``, ``make_users_staff``, ``superuser_group_names`` and ``default_groups`` "
                "are deprecated. Use the ``options`` attribute instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            config.options = {
                "user_settings": {
                    "claim_mappings": {
                        "username": config_model.username_claim,
                        **config_model.claim_mapping,
                    }
                },
                "group_settings": {
                    "claim_mapping": config_model.groups_claim,
                    "sync": config_model.sync_groups,
                    "sync_pattern": config_model.sync_groups_glob_pattern,
                    "make_users_staff": config_model.make_users_staff,
                    "superuser_group_names": config_model.superuser_group_names,
                    "default_groups": config_model.default_groups,
                },
            }
        config.save()

    def _create_or_update_providers(
        self, provider_config_model: OIDCConfigProviderModel
    ) -> None:
        provider, _ = OIDCProvider.objects.update_or_create(
            identifier=provider_config_model.identifier
        )
        form = OIDCProviderForm(
            instance=provider,
            data={
                "identifier": provider_config_model.identifier,
                "oidc_token_use_basic_auth": provider_config_model.oidc_token_use_basic_auth,
                "oidc_use_nonce": provider_config_model.oidc_use_nonce,
                "oidc_nonce_size": provider_config_model.oidc_nonce_size,
                "oidc_state_size": provider_config_model.oidc_state_size,
                **self._get_endpoints(provider_config_model.endpoint_config),
            },
        )
        if not form.is_valid():
            raise ConfigurationRunFailed(
                "Admin OIDC configuration field validation failed",
                form.errors.as_json(),
            )
        form.save()
