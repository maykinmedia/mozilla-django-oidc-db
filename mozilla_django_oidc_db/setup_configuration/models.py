from typing import Annotated, Literal

from django.utils.translation import gettext_lazy as _

from django_setup_configuration.fields import DjangoModelRef
from django_setup_configuration.models import ConfigurationModel
from pydantic import AnyUrl, Discriminator, Field, Tag

from mozilla_django_oidc_db.models import OIDCClient, OIDCProvider

EXAMPLE_REALM = "http://keycloak.local:8080/realms/test"


class OIDCFullProviderConfig(ConfigurationModel):
    oidc_op_authorization_endpoint: AnyUrl = DjangoModelRef(
        OIDCProvider,
        "oidc_op_authorization_endpoint",
        examples=[f"{EXAMPLE_REALM}/openid-connect/auth"],
    )
    oidc_op_token_endpoint: AnyUrl = DjangoModelRef(
        OIDCProvider,
        "oidc_op_token_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/token"],
    )
    oidc_op_user_endpoint: AnyUrl = DjangoModelRef(
        OIDCProvider,
        "oidc_op_user_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/userinfo"],
    )
    oidc_op_logout_endpoint: AnyUrl | Literal[""] = DjangoModelRef(
        OIDCProvider,
        "oidc_op_logout_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/logout"],
    )
    oidc_op_jwks_endpoint: AnyUrl | Literal[""] = DjangoModelRef(
        OIDCProvider,
        "oidc_op_jwks_endpoint",
        examples=[f"{EXAMPLE_REALM}/protocol/openid-connect/certs"],
    )


class OIDCDiscoveryProviderConfig(ConfigurationModel):
    oidc_op_discovery_endpoint: AnyUrl = DjangoModelRef(
        OIDCProvider,
        "oidc_op_discovery_endpoint",
        examples=[f"{EXAMPLE_REALM}/"],
    )


def get_provider_config_model(endpoint_data):
    """Get which configuration model to use for the OIDC provider"""
    if isinstance(endpoint_data, dict):
        discovery_endpoint = endpoint_data.get("oidc_op_discovery_endpoint")
    else:
        discovery_endpoint = getattr(endpoint_data, "oidc_op_discovery_endpoint", None)
    if discovery_endpoint:
        return "discovery"
    return "all"


OIDCProviderConfigUnion = Annotated[
    Annotated[OIDCFullProviderConfig, Tag("all")]
    | Annotated[OIDCDiscoveryProviderConfig, Tag("discovery")],
    Discriminator(get_provider_config_model),
]


class OIDCConfigProviderModel(ConfigurationModel):
    identifier: str = DjangoModelRef(
        OIDCProvider,
        "identifier",
        description="a unique identifier for this OIDC provider.",
        examples=["test-oidc-provider"],
    )
    endpoint_config: OIDCProviderConfigUnion

    class Meta:
        django_model_refs = {
            OIDCProvider: [
                "oidc_token_use_basic_auth",
                "oidc_use_nonce",
                "oidc_nonce_size",
                "oidc_state_size",
            ]
        }


class AdminOIDCConfigurationModelItem(ConfigurationModel):
    identifier: str = DjangoModelRef(
        OIDCClient,
        "identifier",
        description="a unique identifier for this configuration",
        examples=["admin-oidc"],
    )

    enabled: bool = DjangoModelRef(OIDCClient, "enabled", default=True)
    oidc_rp_scopes_list: list[str] = DjangoModelRef(OIDCClient, "oidc_rp_scopes_list")
    options: dict = DjangoModelRef(
        OIDCClient,
        "options",
        default_factory=dict,
        examples=[
            {
                "user_settings": {
                    "claim_mappings": {
                        "username": ["sub"],
                        "email": ["email"],
                        "first_name": ["given_name"],
                        "last_name": ["family_name"],
                    },
                    "username_case_sensitive": False,
                },
                "groups_settings": {
                    "make_users_staff": True,
                    "superuser_group_names": ["superuser"],
                    "sync": True,
                    "sync_pattern": "*",
                    "claim_mapping": ["roles"],
                },
            }
        ],
    )

    endpoint_config: OIDCProviderConfigUnion | None = Field(
        description=_("Configuration for the OIDC Provider endpoints."),
        default=None,
        deprecated="Moved to `providers.endpoint_config`",
    )
    oidc_provider_identifier: str = DjangoModelRef(
        OIDCProvider, "identifier", examples=["test-oidc-provider"], default=""
    )

    ## DEPRECATED FIELDS
    claim_mapping: dict = Field(
        default_factory=lambda: {
            "email": ["email"],
            "first_name": ["given_name"],
            "last_name": ["family_name"],
        },
        description=_("Mapping from User model field names to a path in the claim."),
        deprecated="Moved to `items.options.user_settings.claim_mappings`",
    )
    oidc_token_use_basic_auth: bool = Field(
        default=False,
        description=_(
            "If enabled, the client ID and secret are sent in the HTTP Basic auth "
            "header when obtaining the access token. Otherwise, they are sent in the "
            "request body."
        ),
        deprecated="Moved to `providers.oidc_token_use_basic_auth`",
    )
    oidc_use_nonce: bool = Field(
        default=True,
        description=_("Controls whether the client uses nonce verification"),
        deprecated="Moved to providers.oidc_use_nonce",
    )
    oidc_nonce_size: int = Field(
        default=32,
        description=_(
            "Sets the length of the random string used for nonce verification"
        ),
        deprecated="Moved to `providers.oidc_nonce_size`",
    )
    oidc_state_size: int = Field(
        default=32,
        description=_(
            "Sets the length of the random string used for state verification"
        ),
        deprecated="Moved to `providers.oidc_state_size`",
    )
    # Arrays are overridden to make the typing simpler (the underlying Django field is an ArrayField, which is non-standard)
    username_claim: list[str] = Field(
        default_factory=lambda: ["sub"],
        description=_("Path in the claims to the value to use as username."),
        deprecated="Moved to `items.options.user_settings.claim_mappings.username`",
        examples=[["nested", "username", "claim"]],
    )
    groups_claim: list[str] = Field(
        default_factory=lambda: ["roles"],
        description=_("Path in the claims to the value with group names."),
        deprecated="Moved to `items.options.group_settings.claim_mapping`",
        examples=[["nested", "group", "claim"]],
    )
    superuser_group_names: list[str] = Field(
        default_factory=list,
        description=_("Superuser group names"),
        deprecated="Moved to `items.options.group_settings.superuser_group_names`",
        examples=[["superusers"]],
    )
    default_groups: list[str] = Field(
        default_factory=list,
        description=_("Default group names"),
        deprecated="Moved `items.options.group_settings.default_groups`",
        examples=[["read-only-users"]],
    )
    sync_groups: bool = Field(
        description=_("Whether to sync local groups"),
        deprecated="Moved to `items.options.group_settings.sync`",
        examples=[True],
        default=True,
    )
    sync_groups_glob_pattern: str = Field(
        description=_("Pattern that the group names to sync should follow."),
        deprecated="Moved to `items.options.group_settings.sync_pattern`",
        examples=["*"],
        default="*",
    )
    make_users_staff: bool = Field(
        description=_("Whether to make the users staff."),
        deprecated="Moved to `items.options.groups_settings.make_users_staff`",
        examples=[False],
        default=False,
    )

    class Meta:
        django_model_refs = {
            OIDCClient: [
                "oidc_rp_client_id",
                "oidc_rp_client_secret",
                "oidc_rp_sign_algo",
                "oidc_rp_idp_sign_key",
                "oidc_keycloak_idp_hint",
                "userinfo_claims_source",
            ]
        }
        extra_kwargs = {
            "oidc_rp_client_id": {"examples": ["modify-this"]},
            "oidc_rp_client_secret": {"examples": ["modify-this"]},
            "oidc_rp_idp_sign_key": {"examples": ["modify-this"]},
            "oidc_keycloak_idp_hint": {"examples": ["some-identity-provider"]},
        }


class AdminOIDCConfigurationModel(ConfigurationModel):
    providers: list[OIDCConfigProviderModel] = Field(
        default_factory=list, description=_("List of OIDC providers")
    )
    items: list[AdminOIDCConfigurationModelItem]
