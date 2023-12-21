import fnmatch
import logging
from typing import Any, Dict

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist

from glom import glom
from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as _OIDCAuthenticationBackend,
)

from .mixins import GetAttributeMixin, SoloConfigMixin
from .models import UserInformationClaimsSources
from .utils import obfuscate_claims

logger = logging.getLogger(__name__)


class OIDCAuthenticationBackend(
    GetAttributeMixin, SoloConfigMixin, _OIDCAuthenticationBackend
):
    """
    Modifies the default OIDCAuthenticationBackend to use a configurable claim
    as unique identifier (default `sub`).
    """

    config_identifier_field = "username_claim"
    sensitive_claim_names = []

    def __init__(self, *args, **kwargs):
        self.UserModel = get_user_model()

        # See: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/30
        # `super().__init__` is not called here, because this attempts to initialize
        # the settings (which should be retrieved from `OpenIDConnectConfig`).

        # The retrieval of these settings has been moved to runtime (`__getattribute__`)
        # to avoid a large number of `OpenIDConnectConfig.get_solo` calls when
        # `OIDCAuthenticationBackend.__init__` is called for permission checks

    def retrieve_identifier_claim(self, claims: dict) -> str:
        # NOTE: this does not support the extraction of claims that contain dots "." in
        # their name (e.g. {"foo.bar": "baz"})
        identifier_claim_name = getattr(self.config, self.config_identifier_field)
        unique_id = glom(claims, identifier_claim_name, default="")
        return unique_id

    def get_sensitive_claims_names(self) -> list:
        """
        Defines the claims that should be obfuscated before logging claims.
        Nested claims can be specified by using a dotted path (e.g. "foo.bar.baz")

        NOTE: this does not support claim names that have dots in them, so the following
        claim cannot be marked as a sensitive claim

            {
                "foo.bar": "baz"
            }
        """
        identifier_claim_name = getattr(self.config, self.config_identifier_field)
        return [identifier_claim_name] + self.sensitive_claim_names

    def get_userinfo(self, access_token, id_token, payload):
        """
        Extract the user information, configurable whether to use the ID token or
        the userinfo endpoint for this
        """
        if self.config.userinfo_claims_source == UserInformationClaimsSources.id_token:
            logger.debug("Extracting user information from ID token")
            return payload

        logger.debug("Retrieving user information from userinfo endpoint")
        return super().get_userinfo(access_token, id_token, payload)

    def authenticate(self, *args, **kwargs):
        if not self.config.enabled:
            return None

        return super().authenticate(*args, **kwargs)

    def get_user_instance_values(self, claims) -> Dict[str, Any]:
        """
        Map the names and values of the claims to the fields of the User model
        """
        return {
            model_field: glom(claims, claims_field, default="")
            for model_field, claims_field in self.config.claim_mapping.items()
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

        identifier_claim_name = getattr(self.config, self.config_identifier_field)
        if not glom(claims, identifier_claim_name, default=""):
            logger.error(
                "%s not in OIDC claims, cannot proceed with authentication",
                identifier_claim_name,
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

    def update_user_superuser_status(self, user, claims):
        """
        Assigns superuser status to the user if the user is a member of at least one
        specific group. Superuser status is explicitly removed if the user is not or
        no longer member of at least one of these groups.
        """
        groups_claim = self.config.groups_claim
        superuser_group_names = self.config.superuser_group_names

        if superuser_group_names:
            claim_groups = glom(claims, groups_claim, default=[])
            if set(superuser_group_names) & set(claim_groups):
                user.is_superuser = True
            else:
                user.is_superuser = False
            user.save()

    def update_user_groups(self, user, claims):
        """
        Updates user group memberships based on the group_claim setting.

        Copied and modified from: https://github.com/snok/django-auth-adfs/blob/master/django_auth_adfs/backend.py
        """
        groups_claim = self.config.groups_claim

        if groups_claim:
            # Update the user's group memberships
            django_groups = [group.name for group in user.groups.all()]
            claim_groups = glom(claims, groups_claim, default=[])
            if claim_groups:
                if not isinstance(claim_groups, list):
                    claim_groups = [
                        claim_groups,
                    ]
            else:
                logger.debug(
                    "The configured groups claim '%s' was not found in the access token",
                    groups_claim,
                )
                claim_groups = []
            if sorted(claim_groups) != sorted(django_groups):
                existing_groups = list(
                    Group.objects.filter(name__in=claim_groups).iterator()
                )
                existing_group_names = frozenset(
                    group.name for group in existing_groups
                )
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
