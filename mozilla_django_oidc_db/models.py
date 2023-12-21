from typing import Dict, List

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from django_better_admin_arrayfield.models.fields import ArrayField
from solo.models import SingletonModel, get_cache

import mozilla_django_oidc_db.settings as oidc_settings

from .compat import classproperty


class UserInformationClaimsSources(models.TextChoices):
    userinfo_endpoint = "userinfo_endpoint", _("Userinfo endpoint")
    id_token = "id_token", _("ID token")


def get_default_scopes() -> List[str]:
    """
    Returns the default scopes to request for OpenID Connect logins
    """
    return ["openid", "email", "profile"]


def get_claim_mapping() -> Dict[str, str]:
    # Map (some) claim names from https://openid.net/specs/openid-connect-core-1_0.html#Claims
    # to corresponding field names on the User model
    return {
        "email": "email",
        "first_name": "given_name",
        "last_name": "family_name",
    }


class CachingMixin:
    @classmethod
    def clear_cache(cls):
        cache_name = getattr(
            settings, "OIDC_CACHE", oidc_settings.MOZILLA_DJANGO_OIDC_DB_CACHE
        )
        if cache_name:
            cache = get_cache(cache_name)
            cache_key = cls.get_cache_key()
            cache.delete(cache_key)

    def set_to_cache(self):
        cache_name = getattr(
            settings,
            "MOZILLA_DJANGO_OIDC_DB_CACHE",
            oidc_settings.MOZILLA_DJANGO_OIDC_DB_CACHE,
        )
        if not cache_name:
            return None
        cache = get_cache(cache_name)
        cache_key = self.get_cache_key()
        timeout = getattr(
            settings,
            "MOZILLA_DJANGO_OIDC_DB_CACHE_TIMEOUT",
            oidc_settings.MOZILLA_DJANGO_OIDC_DB_CACHE_TIMEOUT,
        )
        cache.set(cache_key, self, timeout)

    @classmethod
    def get_cache_key(cls) -> str:
        prefix = cls.custom_oidc_db_prefix or getattr(
            settings,
            "MOZILLA_DJANGO_OIDC_DB_PREFIX",
            oidc_settings.MOZILLA_DJANGO_OIDC_DB_PREFIX,
        )
        return "%s:%s" % (prefix, cls.__name__.lower())

    @classmethod
    def get_solo(cls) -> SingletonModel:
        cache_name = getattr(
            settings,
            "MOZILLA_DJANGO_OIDC_DB_CACHE",
            oidc_settings.MOZILLA_DJANGO_OIDC_DB_CACHE,
        )
        if not cache_name:
            obj, created = cls.objects.get_or_create(pk=cls.singleton_instance_id)
            return obj
        cache = get_cache(cache_name)
        cache_key = cls.get_cache_key()
        obj = cache.get(cache_key)
        if not obj:
            obj, created = cls.objects.get_or_create(pk=cls.singleton_instance_id)
            obj.set_to_cache()
        return obj


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
    oidc_exempt_urls = ArrayField(
        verbose_name=_("URLs exempt from session renewal"),
        base_field=models.CharField(_("Exempt URL"), max_length=1000),
        default=list,
        blank=True,
        help_text=_(
            "This is a list of absolute url paths, regular expressions for url paths, "
            "or Django view names. This plus the mozilla-django-oidc urls are exempted "
            "from the session renewal by the SessionRefresh middleware."
        ),
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

    @property
    def oidc_rp_scopes(self) -> str:
        """
        Scopes should be formatted as a string with spaces
        """
        return " ".join(self.oidc_rp_scopes_list)

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return force_str(self._meta.verbose_name)


class OpenIDConnectConfig(CachingMixin, OpenIDConnectConfigBase):
    """
    Configuration for authentication/authorization via OpenID connect
    """

    username_claim = models.CharField(
        _("username claim"),
        max_length=50,
        default="sub",
        help_text=_("The name of the OIDC claim that is used as the username"),
    )
    claim_mapping = models.JSONField(
        _("claim mapping"),
        default=get_claim_mapping,
        help_text=("Mapping from user-model fields to OIDC claims"),
    )
    groups_claim = models.CharField(
        _("groups claim"),
        max_length=50,
        default="roles",
        help_text=_(
            "The name of the OIDC claim that holds the values to map to local user groups."
        ),
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
            except models.FieldDoesNotExist:
                raise ValidationError(
                    {
                        "claim_mapping": _(
                            "Field {field} does not exist on the user model"
                        ).format(field=field)
                    }
                )

        if User.USERNAME_FIELD in self.claim_mapping:
            raise ValidationError(
                {
                    "claim_mapping": _(
                        "The username field may not be in the claim mapping"
                    ),
                }
            )

    @classproperty
    def custom_oidc_db_prefix(cls) -> str:
        """
        Cache prefix that can be overridden
        """
        return oidc_settings.MOZILLA_DJANGO_OIDC_DB_PREFIX
