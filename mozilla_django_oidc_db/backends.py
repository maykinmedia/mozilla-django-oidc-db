import fnmatch
import logging
from typing import Any, TypeVar, cast

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser, Group
from django.core.exceptions import ObjectDoesNotExist

import requests
from glom import Path, glom
from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as _OIDCAuthenticationBackend,
)

from .jwt import verify_and_decode_token
from .mixins import GetAttributeMixin, SoloConfigMixin
from .models import OpenIDConnectConfig, UserInformationClaimsSources
from .utils import extract_content_type, obfuscate_claims

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=OpenIDConnectConfig)


class MissingIdentifierClaim(Exception):
    def __init__(self, claim_bits: list[str], *args, **kwargs):
        self.claim_bits = claim_bits
        super().__init__(*args, **kwargs)


class OIDCAuthenticationBackend(
    GetAttributeMixin, SoloConfigMixin[T], _OIDCAuthenticationBackend
):
    """
    Modifies the default OIDCAuthenticationBackend to use a configurable claim
    as unique identifier (default `sub`).
    """

    config_identifier_field = "username_claim"
    sensitive_claim_names: list[list[str]] = []

    def __init__(self, *args, **kwargs):
        # django-stubs returns AbstractBaseUser, but we depend on properties of
        # AbstractUser.
        self.UserModel = cast(AbstractUser, get_user_model())

        # See: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/30
        # `super().__init__` is not called here, because this attempts to initialize
        # the settings (which should be retrieved from `OpenIDConnectConfig`).

        # The retrieval of these settings has been moved to runtime (`__getattribute__`)
        # to avoid a large number of `OpenIDConnectConfig.get_solo` calls when
        # `OIDCAuthenticationBackend.__init__` is called for permission checks

    def retrieve_identifier_claim(
        self, claims: dict, raise_on_empty: bool = False
    ) -> str:
        claim_bits = getattr(self.config, self.config_identifier_field)
        unique_id = glom(claims, Path(*claim_bits), default="")
        if raise_on_empty and not unique_id:
            raise MissingIdentifierClaim(claim_bits=claim_bits)
        return unique_id

    def get_sensitive_claims_names(self) -> list[list[str]]:
        """
        Defines the claims that should be obfuscated before logging claims.

        Nested claims are represented with a path of bits (e.g. ["foo", "bar", "baz"]).
        Claims with dots in them are supported, e.g. ["foo.bar"].
        """
        identifier_claim_bits: list[str] = getattr(
            self.config, self.config_identifier_field
        )
        return [identifier_claim_bits] + self.sensitive_claim_names

    def get_userinfo(self, access_token, id_token, payload):
        """
        Extract the user information, configurable whether to use the ID token or
        the userinfo endpoint for this
        """
        if self.config.userinfo_claims_source == UserInformationClaimsSources.id_token:
            logger.debug("Extracting user information from ID token")
            return payload

        logger.debug("Retrieving user information from userinfo endpoint")

        # copy of upstream get_userinfo which doesn't support application/jwt yet.
        # Overridden to handle application/jwt responses.
        # See https://github.com/mozilla/mozilla-django-oidc/issues/517
        #
        # Specifying the preferred format in the ``Accept`` header does not work with
        # Keycloak, as it depends on the client settings.
        user_response = requests.get(
            self.OIDC_OP_USER_ENDPOINT,
            headers={
                "Authorization": "Bearer {0}".format(access_token),
            },
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        user_response.raise_for_status()

        # From https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        #
        # > The UserInfo Endpoint MUST return a content-type header to indicate which
        # > format is being returned.
        content_type = extract_content_type(user_response.headers["Content-Type"])
        match content_type:
            case "application/json":
                # the default case of upstream library
                return user_response.json()
            case "application/jwt":
                token = user_response.content
                # get the key from the configured keys endpoint
                # XXX: tested with asymmetric encryption. algorithms like HS256 rely on
                # out-of-band key exchange and are currently not supported until such a
                # case arrives.
                key = self.retrieve_matching_jwk(token)
                payload = verify_and_decode_token(token, key)
                return payload
            case _:
                raise ValueError(
                    f"Got an invalid Content-Type header value ({content_type}) "
                    "according to OpenID Connect Core 1.0 standard. Contact your "
                    "vendor."
                )

    def authenticate(self, *args, **kwargs):
        if not self.config.enabled:
            return None

        return super().authenticate(*args, **kwargs)

    def get_user_instance_values(self, claims) -> dict[str, Any]:
        """
        Map the names and values of the claims to the fields of the User model
        """
        return {
            model_field: glom(claims, Path(*claim_bits), default="")
            for model_field, claim_bits in self.config.claim_mapping.items()
        }

    def create_user(self, claims):
        """Return object for a newly created user account."""
        unique_id = self.retrieve_identifier_claim(claims)

        logger.debug("Creating OIDC user: %s", unique_id)

        user = self.UserModel.objects.create_user(
            **{self.UserModel.USERNAME_FIELD: unique_id}
        )
        self.update_user(user, claims)

        return user

    def filter_users_by_claims(self, claims):
        """Return all users matching the specified subject."""
        unique_id = self.retrieve_identifier_claim(claims)

        if not unique_id:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(
            **{f"{self.UserModel.USERNAME_FIELD}__iexact": unique_id}
        )

    def verify_claims(self, claims) -> bool:
        """Verify the provided claims to decide if authentication should be allowed."""
        if not claims:
            return False

        claims_to_obfuscate = self.get_sensitive_claims_names()
        obfuscated_claims = obfuscate_claims(claims, claims_to_obfuscate)

        logger.debug("OIDC claims received: %s", obfuscated_claims)

        # check if we have an identifier
        try:
            self.retrieve_identifier_claim(claims, raise_on_empty=True)
        except MissingIdentifierClaim as exc:
            logger.error(
                "'%s' not in OIDC claims, cannot proceed with authentication",
                " > ".join(exc.claim_bits),
                exc_info=exc,
            )
            return False
        return True

    def update_user(self, user, claims):
        """Update existing user with new claims, if necessary save, and return user"""
        values = self.get_user_instance_values(claims)
        for field, value in values.items():
            setattr(user, field, value)
        logger.debug("Updating OIDC user %s with: %s", user, values)

        # Users can only be promoted to staff. Staff rights are never taken by OIDC.
        if self.config.make_users_staff and not user.is_staff:
            user.is_staff = True
            user.save(update_fields=["is_staff"])

        user.save(update_fields=values.keys())

        self.update_user_superuser_status(user, claims)

        self.update_user_groups(user, claims)
        self.update_user_default_groups(user)

        return user

    def _retrieve_groups_claim(self, claims: dict[str, Any]) -> list[str]:
        groups_claim_bits = self.config.groups_claim
        return glom(claims, Path(*groups_claim_bits), default=[])

    def update_user_superuser_status(self, user, claims) -> None:
        """
        Assigns superuser status to the user if the user is a member of at least one
        specific group. Superuser status is explicitly removed if the user is not or
        no longer member of at least one of these groups.
        """
        # can't do an isinstance check here
        superuser_group_names = cast(list[str], self.config.superuser_group_names)

        if not superuser_group_names:
            return

        claim_groups = self._retrieve_groups_claim(claims)
        if set(superuser_group_names) & set(claim_groups):
            user.is_superuser = True
        else:
            user.is_superuser = False
        user.save()

    def update_user_groups(self, user, claims) -> None:
        """
        Updates user group memberships based on the group_claim setting.

        Copied and modified from: https://github.com/snok/django-auth-adfs/blob/master/django_auth_adfs/backend.py
        """
        group_claim_bits: list[str] = self.config.groups_claim
        if not group_claim_bits:
            return

        claim_groups = self._retrieve_groups_claim(claims)

        # Update the user's group memberships
        django_groups = [group.name for group in user.groups.all()]
        if claim_groups:
            if not isinstance(claim_groups, list):
                claim_groups = [
                    claim_groups,
                ]
        else:
            logger.debug(
                "The configured groups claim '%s' was not found in the access token",
                " > ".join(group_claim_bits),
            )
            claim_groups = []
        if sorted(claim_groups) != sorted(django_groups):
            existing_groups = list(
                Group.objects.filter(name__in=claim_groups).iterator()
            )
            existing_group_names = frozenset(group.name for group in existing_groups)
            new_groups = []
            if self.config.sync_groups:
                # Only sync groups that match the supplied glob pattern
                new_groups = [
                    Group.objects.get_or_create(name=name)[0]
                    for name in fnmatch.filter(
                        claim_groups,
                        self.config.sync_groups_glob_pattern,
                    )
                    if name not in existing_group_names
                ]
            else:
                for name in claim_groups:
                    if name not in existing_group_names:
                        try:
                            group = Group.objects.get(name=name)
                            new_groups.append(group)
                        except ObjectDoesNotExist:
                            pass
            user.groups.set(existing_groups + new_groups)

    def update_user_default_groups(self, user):
        """
        Updates user group memberships based on the configured default groups.
        """
        default_groups = self.config.default_groups.all()
        user.groups.set(user.groups.union(default_groups))
