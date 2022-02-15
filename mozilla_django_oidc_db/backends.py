import fnmatch
import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist

from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as _OIDCAuthenticationBackend,
)

from .mixins import SoloConfigMixin

logger = logging.getLogger(__name__)


class OIDCAuthenticationBackend(SoloConfigMixin, _OIDCAuthenticationBackend):
    """
    Modifies the default OIDCAuthenticationBackend to use a configurable claim
    as unique identifier (default `sub`).
    """

    def __getattribute__(self, attr):
        if attr.startswith("OIDC"):
            return self.get_settings(attr, None)
        return super().__getattribute__(attr)

    def __init__(self, *args, **kwargs):
        self.UserModel = get_user_model()

        # See: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/30
        # `super().__init__` is not called here, because this attempts to initialize
        # the settings (which should be retrieved from `OpenIDConnectConfig`).

        # The retrieval of these settings has been moved to runtime (`__getattribute__`)
        # to avoid a large number of `OpenIDConnectConfig.get_solo` calls when
        # `OIDCAuthenticationBackend.__init__` is called for permission checks

    def authenticate(self, *args, **kwargs):
        if not self.config.enabled:
            return None

        return super().authenticate(*args, **kwargs)

    def get_user_instance_values(self, claims):
        """
        Map the names and values of the claims to the fields of the User model
        """
        return {
            model_field: claims.get(claims_field, "")
            for model_field, claims_field in self.config.claim_mapping.items()
        }

    def create_user(self, claims):
        """Return object for a newly created user account."""
        username_claim = self.config.username_claim
        unique_id = claims.get(username_claim)

        logger.debug("Creating OIDC user: %s", unique_id)

        user = self.UserModel.objects.create_user(
            **{self.UserModel.USERNAME_FIELD: unique_id}
        )
        self.update_user(user, claims)

        return user

    def filter_users_by_claims(self, claims):
        """Return all users matching the specified subject."""
        username_claim = self.config.username_claim
        unique_id = claims.get(username_claim)

        if not unique_id:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(
            **{f"{self.UserModel.USERNAME_FIELD}__iexact": unique_id}
        )

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""
        scopes = self.get_settings("OIDC_RP_SCOPES", "openid email")

        logger.debug("OIDC claims received: %s", claims)

        username_claim = self.config.username_claim

        if username_claim not in claims:
            logger.error(
                "%s not in OIDC claims, cannot proceed with authentication",
                username_claim,
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

        self.update_user_groups(user, claims)

        return user

    def update_user_groups(self, user, claims):
        """
        Updates user group memberships based on the group_claim setting.

        Copied and modified from: https://github.com/snok/django-auth-adfs/blob/master/django_auth_adfs/backend.py
        """
        groups_claim = self.config.groups_claim

        if groups_claim:
            # Update the user's group memberships
            django_groups = [group.name for group in user.groups.all()]

            if groups_claim in claims:
                claim_groups = claims[groups_claim]
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
