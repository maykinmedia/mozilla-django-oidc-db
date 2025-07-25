import factory

from ..models import OIDCClient, OIDCProvider


class OIDCProviderFactory(factory.django.DjangoModelFactory):
    identifier = factory.Faker("word")

    oidc_op_discovery_endpoint = factory.Faker("url")

    oidc_op_jwks_endpoint = factory.LazyAttribute(
        lambda provider: f"{provider.oidc_op_discovery_endpoint}protocol/openid-connect/certs"
    )
    oidc_op_authorization_endpoint = factory.LazyAttribute(
        lambda provider: f"{provider.oidc_op_discovery_endpoint}openid-connect/auth"
    )
    oidc_op_token_endpoint = factory.LazyAttribute(
        lambda provider: f"{provider.oidc_op_discovery_endpoint}protocol/openid-connect/token"
    )
    oidc_op_user_endpoint = factory.LazyAttribute(
        lambda provider: f"{provider.oidc_op_discovery_endpoint}protocol/openid-connect/userinfo"
    )
    oidc_op_logout_endpoint = factory.LazyAttribute(
        lambda provider: f"{provider.oidc_op_discovery_endpoint}protocol/openid-connect/logout"
    )

    class Meta:
        model = OIDCProvider
        django_get_or_create = ("identifier",)


class OIDCClientFactory(factory.django.DjangoModelFactory):
    oidc_provider = factory.SubFactory(OIDCProviderFactory)
    identifier = factory.Faker("word")
    oidc_rp_client_id = factory.Faker("word")
    oidc_rp_client_secret = factory.Faker("word")
    options = factory.Dict({"bla": "bla"})

    class Meta:
        model = OIDCClient
        django_get_or_create = ("identifier",)

    class Params:
        with_admin_options = factory.Trait(
            options=factory.Dict(
                {
                    "user_settings": {
                        "claim_mappings": {
                            "username": ["sub"],
                            "email": ["email"],
                            "last_name": [],
                            "first_name": [],
                        },
                        "username_case_sensitive": False,
                        "sensitive_claims": [],
                    },
                    "groups_settings": {
                        "make_users_staff": True,
                        "sync": False,
                        "default_groups": [],
                        "claim_mapping": [],
                        "superuser_group_names": [],
                        "sync_pattern": "*",
                    },
                }
            )
        )
