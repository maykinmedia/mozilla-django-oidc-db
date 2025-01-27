from typing import Literal, Union

from django_setup_configuration.fields import DjangoModelRef
from django_setup_configuration.models import ConfigurationModel
from pydantic import AnyUrl, Discriminator, Field, Tag
from typing_extensions import Annotated

from mozilla_django_oidc_db.models import OpenIDConnectConfig

EXAMPLE_REALM = "http://keycloak.local:8080/realms/test"


class OIDCFullEndpointConfig(ConfigurationModel):
    oidc_op_authorization_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig,
        "oidc_op_authorization_endpoint",
        examples=[f"{EXAMPLE_REALM}/openid-connect/auth"],
    )
    oidc_op_token_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig,
        "oidc_op_token_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/token"],
    )
    oidc_op_user_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig,
        "oidc_op_user_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/userinfo"],
    )
    oidc_op_logout_endpoint: AnyUrl | Literal[""] = DjangoModelRef(
        OpenIDConnectConfig,
        "oidc_op_logout_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/logout"],
    )
    oidc_op_jwks_endpoint: AnyUrl | Literal[""] = DjangoModelRef(
        OpenIDConnectConfig,
        "oidc_op_jwks_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/certs"],
    )


class OIDCDiscoveryEndpoint(ConfigurationModel):
    oidc_op_discovery_endpoint: AnyUrl = DjangoModelRef(
        OpenIDConnectConfig,
        "oidc_op_discovery_endpoint",
        examples=[f"{EXAMPLE_REALM}/"],
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


class AdminOIDCConfigurationModelItem(ConfigurationModel):
    # Currently unused because we use a SingletonModel, but this will be relevant in the
    # future
    identifier: str = Field(
        description="a unique identifier for this configuration",
        examples=["admin-oidc"],
    )

    # Change default to True
    enabled: bool = DjangoModelRef(OpenIDConnectConfig, "enabled", default=True)

    # Json
    claim_mapping: dict = DjangoModelRef(OpenIDConnectConfig, "claim_mapping")

    # Arrays are overridden to make the typing simpler (the underlying Django field is an ArrayField, which is non-standard)
    username_claim: list[str] = DjangoModelRef(
        OpenIDConnectConfig,
        "username_claim",
        examples=[["nested", "username", "claim"]],
    )
    groups_claim: list[str] = DjangoModelRef(OpenIDConnectConfig, "groups_claim")
    superuser_group_names: list[str] = DjangoModelRef(
        OpenIDConnectConfig, "superuser_group_names", examples=[["superusers"]]
    )
    default_groups: list[str] = DjangoModelRef(
        OpenIDConnectConfig,
        "default_groups",
        examples=[["read-only-users"]],
        default=list,
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
        extra_kwargs = {
            "oidc_rp_client_id": {"examples": ["modify-this"]},
            "oidc_rp_client_secret": {"examples": ["modify-this"]},
            "oidc_rp_idp_sign_key": {"examples": ["modify-this"]},
            "oidc_keycloak_idp_hint": {"examples": ["some-identity-provider"]},
        }


class AdminOIDCConfigurationModel(ConfigurationModel):
    items: list[AdminOIDCConfigurationModelItem]
