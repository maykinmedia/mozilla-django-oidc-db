import logging

from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as _OIDCAuthenticationBackend,
)

from .mixins import SoloConfigMixin
from .models import OpenIDConnectConfig

logger = logging.getLogger(__name__)


class OIDCAuthenticationBackend(SoloConfigMixin, _OIDCAuthenticationBackend):
    """
    Modifies the default OIDCAuthenticationBackend to use the `sub` claim
    as unique identifier.
    """

    # Map (some) claim names from https://openid.net/specs/openid-connect-core-1_0.html#Claims
    # to corresponding field names on the User model
    claims_field_mapping = {
        "sub": "username",
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
    }

    def __init__(self, *args, **kwargs):
        config = OpenIDConnectConfig.get_solo()

        if not config.enabled:
            return

        super().__init__(*args, **kwargs)

    def authenticate(self, *args, **kwargs):
        config = OpenIDConnectConfig.get_solo()

        if not config.enabled:
            return None

        return super().authenticate(*args, **kwargs)

    def get_user_instance_values(self, claims):
        """
        Map the names and values of the claims to the fields of the User model
        """
        return {
            model_field: claims.get(claims_field, "")
            for claims_field, model_field in self.claims_field_mapping.items()
        }

    def create_user(self, claims):
        """Return object for a newly created user account."""
        values = self.get_user_instance_values(claims)
        return self.UserModel.objects.create_user(**values)

    def filter_users_by_claims(self, claims):
        """Return all users matching the specified subject."""
        sub = claims.get("sub")

        if not sub:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username__iexact=sub)

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""
        scopes = self.get_settings("OIDC_RP_SCOPES", "openid email")

        if "sub" not in claims:
            logger.error("`sub` not in OIDC claims, cannot proceed with authentication")
            return False
        return True

    def update_user(self, user, claims):
        """Update existing user with new claims, if necessary save, and return user"""
        values = self.get_user_instance_values(claims)
        for field, value in values.items():
            setattr(user, field, value)
        user.save(update_fields=values.keys())
        return user
