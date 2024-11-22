from __future__ import annotations

from collections.abc import Collection
from typing import ClassVar

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import models
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField, JSONField
from solo import settings as solo_settings
from solo.models import SingletonModel

from .constants import CLAIM_MAPPING_SCHEMA
from .fields import ClaimField, ClaimFieldDefault
from .typing import ClaimPath, DjangoView


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


class OpenIDConnectConfigBase(SingletonModel):
    """
    Defines the required fields for a config to establish an OIDC connection
    """

    enabled = models.BooleanField(
        _("enable"),
        default=False,
        help_text=_(
            "Indicates whether OpenID Connect for authentication/authorization is enabled"
        ),
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
    oidc_token_use_basic_auth = models.BooleanField(
        _("Use Basic auth for token endpoint"),
        default=False,
        help_text=_(
            "If enabled, the client ID and secret are sent in the HTTP Basic auth "
            "header when obtaining the access token. Otherwise, they are sent in the "
            "request body.",
        ),
    )
    oidc_op_user_endpoint = models.URLField(
        _("User endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider userinfo endpoint"),
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
    oidc_op_logout_endpoint = models.URLField(
        _("Logout endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider logout endpoint"),
        blank=True,
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
            "Indicates the source from which the user information claims should be extracted."
        ),
    )

    # extra (static) configuration
    sensitive_claims: ClassVar[Collection[ClaimPath]] = []

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return force_str(self._meta.verbose_name)

    @classmethod
    def get_cache_key(cls):
        """
        Overridden cache key to take into account the app label.
        """
        solo_prefix = getattr(
            settings, "SOLO_CACHE_PREFIX", solo_settings.SOLO_CACHE_PREFIX
        )
        prefix: str = getattr(settings, "MOZILLA_DJANGO_OIDC_DB_PREFIX", solo_prefix)
        return ":".join([prefix, cls._meta.app_label, str(cls._meta.model_name)])

    @property
    def oidc_rp_scopes(self) -> str:
        """
        Scopes should be formatted as a string with spaces
        """
        return " ".join(self.oidc_rp_scopes_list)

    @property
    def oidcdb_sensitive_claims(self) -> Collection[ClaimPath]:
        """
        Determine the claims holding sensitive values.
        """
        return [self.oidcdb_username_claim] + list(self.sensitive_claims)

    @property
    def oidcdb_username_claim(self) -> ClaimPath:
        """
        The claim to read to extract the value for the username field.
        """
        return ["sub"]

    @property
    def oidcdb_userinfo_claims_source(self) -> UserInformationClaimsSources:
        return self.userinfo_claims_source

    def get_callback_view(self) -> DjangoView:
        """
        Determine the view callable to use for the callback flow.

        The view will only be called with a request argument.
        """
        from .views import default_callback_view

        return default_callback_view


class OpenIDConnectConfig(OpenIDConnectConfigBase):
    """
    Configuration for authentication/authorization via OpenID connect
    """

    username_claim = ClaimField(
        verbose_name=_("username claim"),
        default=ClaimFieldDefault("sub"),
        help_text=_("The name of the OIDC claim that is used as the username"),
    )

    claim_mapping = JSONField(
        _("claim mapping"),
        default=get_claim_mapping,
        help_text=_("Mapping from user-model fields to OIDC claims"),
        schema=CLAIM_MAPPING_SCHEMA,
    )
    groups_claim = ClaimField(
        verbose_name=_("groups claim"),
        default=ClaimFieldDefault("roles"),
        help_text=_(
            "The name of the OIDC claim that holds the values to map to local user groups."
        ),
        blank=True,
    )

    sync_groups = models.BooleanField(
        _("Create local user groups if they do not exist yet"),
        default=True,
        help_text=_(
            "If checked, local user groups will be created for group names present in "
            "the groups claim, if they do not exist yet locally."
        ),
    )
    sync_groups_glob_pattern = models.CharField(
        _("groups glob pattern"),
        default="*",
        max_length=255,
        help_text=_(
            "The glob pattern that groups must match to be synchronized to "
            "the local database."
        ),
    )
    default_groups = models.ManyToManyField(
        Group,
        verbose_name=_("default groups"),
        blank=True,
        help_text=_(
            "The default groups to which every user logging in with OIDC will be assigned"
        ),
    )

    make_users_staff = models.BooleanField(
        _("make users staff"),
        default=False,
        help_text=_(
            "Users will be flagged as being a staff user automatically. This allows "
            "users to login to the admin interface. By default they have no permissions, even if they are staff."
        ),
    )
    superuser_group_names = ArrayField(
        verbose_name=_("Superuser group names"),
        base_field=models.CharField(_("Superuser group name"), max_length=50),
        default=list,
        blank=True,
        help_text=_(
            "If any of these group names are present in the claims upon login, "
            "the user will be marked as a superuser. If none of these groups are present "
            "the user will lose superuser permissions."
        ),
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration")

    def clean(self):
        super().clean()

        # validate claim mapping
        User = get_user_model()
        for field in self.claim_mapping.keys():
            try:
                User._meta.get_field(field)
            except FieldDoesNotExist as exc:
                raise ValidationError(
                    {
                        "claim_mapping": _(
                            "Field '{field}' does not exist on the user model"
                        ).format(field=field)
                    }
                ) from exc

        if User.USERNAME_FIELD in self.claim_mapping:
            raise ValidationError(
                {
                    "claim_mapping": _(
                        "The username field may not be in the claim mapping"
                    ),
                }
            )

    @property
    def oidcdb_username_claim(self) -> ClaimPath:
        """
        The claim to read to extract the value for the username field.
        """
        username_claim: ClaimPath = self.username_claim  # type: ignore
        return username_claim

    @property
    def oidcdb_claim_mapping(self) -> dict[str, ClaimPath]:
        return self.claim_mapping

    @property
    def oidcdb_groups_claim(self) -> ClaimPath:
        return self.groups_claim  # type: ignore

    @property
    def oidcdb_default_groups(self) -> Collection[str]:
        return self.default_groups.values_list("name", flat=True)

    @property
    def oidcdb_sync_missing_groups(self) -> bool:
        return self.sync_groups

    @property
    def oidcdb_sync_groups_glob_pattern(self) -> str:
        return self.sync_groups_glob_pattern

    @property
    def oidcdb_make_users_staff(self) -> bool:
        return self.make_users_staff

    @property
    def oidcdb_superuser_group_names(self) -> Collection[str]:
        return self.superuser_group_names  # type: ignore

    def get_callback_view(self):
        from .views import admin_callback_view

        return admin_callback_view
