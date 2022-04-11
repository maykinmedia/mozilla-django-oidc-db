from django.db import models

from solo.models import SingletonModel


def migrate_endpoints_forward(
    config_singleton_model: SingletonModel, endpoints_config_model: models.Model
):
    config = config_singleton_model.objects.first()
    if not config or config.endpoints_config:
        return

    endpoints_config = endpoints_config_model.objects.create(
        oidc_op_discovery_endpoint=config.oidc_op_discovery_endpoint,
        oidc_op_jwks_endpoint=config.oidc_op_jwks_endpoint,
        oidc_op_authorization_endpoint=config.oidc_op_authorization_endpoint,
        oidc_op_token_endpoint=config.oidc_op_token_endpoint,
        oidc_op_user_endpoint=config.oidc_op_user_endpoint,
    )

    config.endpoints_config = endpoints_config
    config.save()


def migrate_endpoints_backward(
    config_singleton_model: SingletonModel, endpoints_config_model: models.Model
):
    config = config_singleton_model.objects.first()
    if not config or not config.endpoints_config:
        return

    config.oidc_op_discovery_endpoint = (
        config.endpoints_config.oidc_op_discovery_endpoint
    )
    config.oidc_op_jwks_endpoint = config.endpoints_config.oidc_op_jwks_endpoint
    config.oidc_op_authorization_endpoint = (
        config.endpoints_config.oidc_op_authorization_endpoint
    )
    config.oidc_op_token_endpoint = config.endpoints_config.oidc_op_token_endpoint
    config.oidc_op_user_endpoint = config.endpoints_config.oidc_op_user_endpoint

    config.save()
