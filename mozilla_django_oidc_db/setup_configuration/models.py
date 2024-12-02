from typing import Union

from django_setup_configuration.fields import DjangoModelRef
from django_setup_configuration.models import ConfigurationModel
from pydantic import AnyUrl, Discriminator, Tag
from typing_extensions import Annotated

from mozilla_django_oidc_db.models import OpenIDConnectConfig


class OIDCFullEndpointConfig(ConfigurationModel):
    oidc_op_authorization_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig, "oidc_op_authorization_endpoint"
    )
    oidc_op_token_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig, "oidc_op_token_endpoint"
    )
    oidc_op_user_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig, "oidc_op_user_endpoint"
    )


class OIDCDiscoveryEndpoint(ConfigurationModel):
    oidc_op_discovery_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig, "oidc_op_discovery_endpoint", default=None
    )


def get_endpoint_endpoint_model(endpoint_data):

    if isinstance(endpoint_data, dict):
        discovery_endpoint = endpoint_data.get("oidc_op_discovery_endpoint")
    else:
        discovery_endpoint = getattr(endpoint_data, "oidc_op_discovery_endpoint", None)
    if discovery_endpoint:
        return "discovery"
    return "all"


EndpointConfigUnion = Annotated[
    Union[
        Annotated[OIDCFullEndpointConfig, Tag("all")],
        Annotated[OIDCDiscoveryEndpoint, Tag("discovery")],
    ],
    Discriminator(get_endpoint_endpoint_model),
]


class AdminOIDCConfigurationModel(ConfigurationModel):

    # Change default to True
    enabled: bool = DjangoModelRef(OpenIDConnectConfig, "enabled", default=True)

    # Json
    claim_mapping: dict = DjangoModelRef(OpenIDConnectConfig, "claim_mapping")

    # Arrays are overridden to make the typing simpler (the underlying Django field is an ArrayField, which is non-standard)
    username_claim: list[str] = DjangoModelRef(OpenIDConnectConfig, "username_claim")
    groups_claim: list[str] = DjangoModelRef(OpenIDConnectConfig, "groups_claim")
    superuser_group_names: list[str] = DjangoModelRef(
        OpenIDConnectConfig, "superuser_group_names"
    )
    default_groups: list[str] = DjangoModelRef(
        OpenIDConnectConfig, "superuser_group_names"
    )
    oidc_rp_scopes_list: list[str] = DjangoModelRef(
        OpenIDConnectConfig, "oidc_rp_scopes_list"
    )

    endpoint_config: EndpointConfigUnion

    class Meta:
        django_model_refs = {
            OpenIDConnectConfig: [
                "oidc_rp_client_id",
                "oidc_rp_client_secret",
                "oidc_token_use_basic_auth",
                "oidc_rp_sign_algo",
                "oidc_rp_idp_sign_key",
                "oidc_op_logout_endpoint",
                "oidc_op_jwks_endpoint",
                "oidc_use_nonce",
                "oidc_nonce_size",
                "oidc_state_size",
                "oidc_keycloak_idp_hint",
                "userinfo_claims_source",
                "sync_groups",
                "sync_groups_glob_pattern",
                "make_users_staff",
            ]
        }
