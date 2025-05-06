from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField, JSONField

from .registry import register as registry


# Removed. But left here so that proxy models that in the migrations have
# bases=("mozilla_django_oidc_db.openidconnectconfig",),
# can still run their migrations.
class OpenIDConnectConfig(models.Model):
    class Meta:
        managed = False


def get_options_schema(instance: "OIDCConfig") -> JSONField:
    plugin = registry[instance.identifier]
    return plugin.get_schema()


class UserInformationClaimsSources(models.TextChoices):
    userinfo_endpoint = "userinfo_endpoint", _("Userinfo endpoint")
    id_token = "id_token", _("ID token")


def get_default_scopes() -> list[str]:
    """
    Returns the default scopes to request for OpenID Connect logins
    """
    return ["openid", "email", "profile"]


def get_claim_mapping() -> dict[str, list[str]]:
    # Map (some) claim names from https://openid.net/specs/openid-connect-core-1_0.html#Claims
    # to corresponding field names on the User model
    return {
        "email": ["email"],
        "first_name": ["given_name"],
        "last_name": ["family_name"],
    }


class OIDCProviderConfig(models.Model):
    """
    Model to configure settings regarding a particular OIDC Provider (OP).
    """

    identifier = models.SlugField(
        unique=True,
        verbose_name=_("identifier"),
        help_text=_("Unique identifier for a configuration of a OIDC provider."),
        max_length=255,
    )

    oidc_op_discovery_endpoint = models.URLField(
        _("Discovery endpoint"),
        max_length=1000,
        help_text=_(
            "URL of your OpenID Connect provider discovery endpoint ending with a slash "
            "(`.well-known/...` will be added automatically). "
            "If this is provided, the remaining endpoints can be omitted, as "
            "they will be derived from this endpoint."
        ),
        blank=True,
    )
    oidc_op_jwks_endpoint = models.URLField(
        _("JSON Web Key Set endpoint"),
        max_length=1000,
        help_text=_(
            "URL of your OpenID Connect provider JSON Web Key Set endpoint. "
            "Required if `RS256` is used as signing algorithm."
        ),
        blank=True,
    )
    oidc_op_authorization_endpoint = models.URLField(
        _("Authorization endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider authorization endpoint"),
    )
    oidc_op_token_endpoint = models.URLField(
        _("Token endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider token endpoint"),
    )
    oidc_op_user_endpoint = models.URLField(
        _("User endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider userinfo endpoint"),
    )
    oidc_op_logout_endpoint = models.URLField(
        _("Logout endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider logout endpoint"),
        blank=True,
    )

    class Meta:
        verbose_name = _("OIDC Provider configuration")
        verbose_name_plural = _("OIDC Provider configurations")

    def __str__(self):
        return _("OIDC Provider %(identifier)s") % {"identifier": self.identifier}


class OIDCConfig(models.Model):
    """Model to configure the settings of the Relying Party (RP) to connect to the specified OIDC Provider (OP)."""

    identifier = models.SlugField(
        unique=True,
        verbose_name=_("identifier"),
        help_text=_("Unique identifier for a configuration."),
        max_length=255,
    )

    enabled = models.BooleanField(
        _("enable"),
        default=False,
        help_text=_(
            "Indicates whether OpenID Connect for authentication/authorization is enabled"
        ),
    )
    oidc_provider_config = models.ForeignKey(
        to=OIDCProviderConfig,
        on_delete=models.PROTECT,
        verbose_name=_("OIDC Provider configuration"),
        help_text=_("Specifies which OIDC Provider configuration to use."),
        # Needed so that we can create empty models at startup
        null=True,
    )

    oidc_rp_client_id = models.CharField(
        _("OpenID Connect client ID"),
        max_length=1000,
        help_text=_("OpenID Connect client ID provided by the OIDC Provider"),
    )
    oidc_rp_client_secret = models.CharField(
        _("OpenID Connect secret"),
        max_length=1000,
        help_text=_("OpenID Connect secret provided by the OIDC Provider"),
    )
    oidc_rp_sign_algo = models.CharField(
        _("OpenID sign algorithm"),
        max_length=50,
        help_text=_("Algorithm the Identity Provider uses to sign ID tokens"),
        default="HS256",
    )
    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes,
        blank=True,
        help_text=_("OpenID Connect scopes that are requested during login"),
    )
    oidc_rp_idp_sign_key = models.CharField(
        _("Sign key"),
        max_length=1000,
        help_text=_(
            "Key the Identity Provider uses to sign ID tokens in the case of an RSA sign algorithm. "
            "Should be the signing key in PEM or DER format."
        ),
        blank=True,
    )
    oidc_token_use_basic_auth = models.BooleanField(
        _("Use Basic auth for token endpoint"),
        default=False,
        help_text=_(
            "If enabled, the client ID and secret are sent in the HTTP Basic auth "
            "header when obtaining the access token. Otherwise, they are sent in the "
            "request body.",
        ),
    )

    # Advanced settings
    oidc_use_nonce = models.BooleanField(
        _("Use nonce"),
        help_text=_(
            "Controls whether the OpenID Connect client uses nonce verification"
        ),
        default=True,
    )
    oidc_nonce_size = models.PositiveIntegerField(
        _("Nonce size"),
        help_text=_(
            "Sets the length of the random string used for OpenID Connect nonce verification"
        ),
        default=32,
    )
    oidc_state_size = models.PositiveIntegerField(
        _("State size"),
        help_text=_(
            "Sets the length of the random string used for OpenID Connect state verification"
        ),
        default=32,
    )

    # Keycloak specific config
    oidc_keycloak_idp_hint = models.CharField(
        _("Keycloak Identity Provider hint"),
        max_length=1000,
        help_text=_(
            "Specific for Keycloak: parameter that indicates which identity provider "
            "should be used (therefore skipping the Keycloak login screen)."
        ),
        blank=True,
    )

    userinfo_claims_source = models.CharField(
        verbose_name=_("user information claims extracted from"),
        choices=UserInformationClaimsSources.choices,
        max_length=100,
        default=UserInformationClaimsSources.userinfo_endpoint,
        help_text=_(
            "Indicates the source from which the user information claims should be extracted. This can be the ID token or the User Info endpoint."
        ),
    )

    # Additional settings
    check_op_availability = models.BooleanField(
        verbose_name=_("check OIDC Provider availability"),
        default=False,
        help_text=_(
            "Whether to check OIDC Provider availability before doing the authentication request."
        ),
    )

    # Customisable options
    options = JSONField(
        _("options"),
        help_text=_("Options relevant for a specific Identity Provider."),
        schema=get_options_schema,
        default=dict,
    )

    class Meta:
        verbose_name = _("OIDC configuration")
        verbose_name_plural = _("OIDC configurations")

    def __str__(self):
        return _("OIDC Config %(identifier)s") % {"identifier": self.identifier}

    @property
    def oidc_rp_scopes(self) -> str:
        """
        Scopes should be formatted as a string with spaces
        """
        return " ".join(self.oidc_rp_scopes_list)
