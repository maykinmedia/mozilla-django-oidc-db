import factory

from ..models import OIDCConfig, OIDCProviderConfig


class OIDCProviderConfigFactory(factory.django.DjangoModelFactory):
    identifier = factory.Faker("word")

    oidc_op_discovery_endpoint = factory.Faker("uri")
    oidc_op_jwks_endpoint = factory.Faker("uri")
    oidc_op_authorization_endpoint = factory.Faker("uri")
    oidc_op_token_endpoint = factory.Faker("uri")
    oidc_op_user_endpoint = factory.Faker("uri")
    oidc_op_logout_endpoint = factory.Faker("uri")

    class Meta:
        model = OIDCProviderConfig
        django_get_or_create = ("identifier",)


class OIDCConfigFactory(factory.django.DjangoModelFactory):
    oidc_provider_config = factory.SubFactory(OIDCProviderConfigFactory)
    identifier = factory.Faker("word")

    class Meta:
        model = OIDCConfig
        django_get_or_create = ("identifier",)
