from __future__ import annotations

import logging
from abc import abstractmethod
from typing import Any, Protocol, TypeAlias, runtime_checkable

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser, AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.http import HttpRequest, HttpResponse

from glom import Path, glom

from .config import get_setting_from_config
from .constants import OIDC_ADMIN_CONFIG_IDENTIFIER
from .exceptions import MissingIdentifierClaim
from .models import OIDCClient
from .registry import register
from .schemas import ADMIN_OPTIONS_SCHEMA
from .typing import ClaimPath, JSONObject
from .utils import get_groups_by_name, obfuscate_claims
from .views import AdminCallbackView

logger = logging.getLogger(__name__)

missing = object()


class OIDCBasePluginProtocol(Protocol):
    identifier: str
    schema: JSONObject

    def get_config(self) -> OIDCClient: ...

    def get_setting(self, attr: str, *args) -> Any: ...

    @abstractmethod
    def get_schema(self) -> JSONObject:
        """Get the JSON schema of the ``options`` field on the :class:`~mozilla_django_oidc_db.models.OIDCClient` model."""
        ...

    @abstractmethod
    def validate_settings(self) -> None:
        """Check the validity of the settings in the provider and client configuration."""
        ...

    @abstractmethod
    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        """Return an HttpResponse based on the callback view specified on the plugin.

        .. code:: python

           def view(self, request: HttpRequest) -> HttpResponse:
               return admin_callback_view(request)

        """
        ...

    @abstractmethod
    def get_extra_params(
        self, request: HttpRequest, extra_params: dict[str, str | bytes]
    ) -> dict[str, str | bytes]: ...


class BaseOIDCPlugin:
    def __init__(self, identifier: str):
        self.identifier = identifier

    def get_config(self) -> OIDCClient:
        return OIDCClient.objects.resolve(self.identifier)

    def get_setting(self, attr: str, *args) -> Any:
        config = self.get_config()

        return get_setting_from_config(config, attr, *args)

    def get_extra_params(
        self, request: HttpRequest, extra_params: dict[str, str | bytes]
    ) -> dict[str, str | bytes]:
        return extra_params


@runtime_checkable
class AnonymousUserOIDCPluginProtocol(OIDCBasePluginProtocol, Protocol):
    def get_or_create_user(
        self,
        access_token: str,
        id_token: str,
        payload: JSONObject,
        request: HttpRequest,
    ) -> AnonymousUser | None: ...


@runtime_checkable
class AbstractUserOIDCPluginProtocol(OIDCBasePluginProtocol, Protocol):
    def create_user(self, claims: JSONObject) -> AbstractUser: ...

    def update_user(self, user: AbstractUser, claims: JSONObject) -> AbstractUser: ...

    def filter_users_by_claims(
        self, claims: JSONObject
    ) -> models.Manager[AbstractUser]:
        """Return all users matching the specified subject."""
        ...

    def verify_claims(self, claims: JSONObject) -> bool:
        """Verify the provided claims to decide if authentication should be allowed."""
        ...


OIDCPlugin: TypeAlias = AbstractUserOIDCPluginProtocol | AnonymousUserOIDCPluginProtocol


admin_callback_view = AdminCallbackView.as_view()


@register(OIDC_ADMIN_CONFIG_IDENTIFIER)
class OIDCAdminPlugin(BaseOIDCPlugin, AbstractUserOIDCPluginProtocol):
    schema = ADMIN_OPTIONS_SCHEMA

    def verify_claims(self, claims: JSONObject) -> bool:
        """Verify the provided claims to decide if authentication should be allowed."""
        assert claims, "Empty claims should have been blocked earlier"

        config = self.get_config()

        sensitive_claims = config.options["user_settings"].get("sensitive_claims", [])
        # The identifier is considered sensitive by default
        sensitive_claims.append(
            config.options["user_settings"]["claim_mappings"]["username"]
        )

        obfuscated_claims = obfuscate_claims(claims, sensitive_claims)

        logger.debug("OIDC claims received: %s", obfuscated_claims)

        # check if we have an identifier
        try:
            self.get_username(claims, raise_on_empty=True)
        except MissingIdentifierClaim as exc:
            logger.error(
                "'%s' not in OIDC claims, cannot proceed with authentication",
                " > ".join(exc.claim_bits),
                exc_info=exc,
            )
            return False
        return True

    def get_username(self, claims: JSONObject, *, raise_on_empty: bool = False) -> str:
        """
        Given the claims, extract the username value.
        """

        config = self.get_config()

        claim_bits = config.options["user_settings"]["claim_mappings"]["username"]
        unique_id = glom(claims, Path(*claim_bits), default="")
        if raise_on_empty and not unique_id:
            raise MissingIdentifierClaim(claim_bits=claim_bits)
        return unique_id

    def validate_settings(self):
        # Equivalent of checks in upstream __init__ method
        config = self.get_config()

        if (
            config.oidc_rp_sign_algo.startswith("RS")
            or config.oidc_rp_sign_algo.startswith("ES")
        ) and (
            config.oidc_rp_idp_sign_key == ""
            and config.oidc_provider
            and config.oidc_provider.oidc_op_jwks_endpoint == ""
        ):
            msg = "{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured."
            raise ImproperlyConfigured(msg.format(config.oidc_rp_sign_algo))

    def filter_users_by_claims(
        self, claims: JSONObject
    ) -> models.Manager[AbstractUser]:
        """Return all users matching the specified subject."""
        UserModel = get_user_model()

        username = self.get_username(claims)
        assert username, (
            "A username must be provided. Did you forget to check empty usernames "
            "in the claim verification?"
        )

        lookup = UserModel.USERNAME_FIELD

        config = self.get_config()
        if not config.options["user_settings"].get("username_case_sensitive", True):
            lookup += "__iexact"

        return UserModel.objects.filter(**{lookup: username})

    def create_user(self, claims: JSONObject) -> AbstractUser:
        """Return object for a newly created user account."""
        username = self.get_username(claims)

        logger.debug("Creating Admin OIDC user: %s", username)

        UserModel = get_user_model()
        user = UserModel.objects.create_user(**{UserModel.USERNAME_FIELD: username})
        self.update_user(user, claims)
        return user

    def update_user(self, user: AbstractUser, claims: JSONObject) -> AbstractUser:
        """
        Update existing user with new claims, if necessary save, and return user.

        This method checks dynamic settings, which are provided by our
        :class:`~mozilla_django_oidc_db.models.OIDCClient` model. If the
        respective fields do not exist on the config model being used, you must make
        sure they exist as Django settings.
        """
        logger.debug("Updating Admin OIDC user %s", user)

        touched_fields: set[str] = set()

        config = self.get_config()

        for model_field, claim_bits in config.options["user_settings"][
            "claim_mappings"
        ].items():
            if model_field == "username":
                # We do not update the username
                continue

            # If no path is specified to a claim, skip it.
            if not claim_bits:
                continue

            value = glom(claims, Path(*claim_bits), default=missing)
            if value is missing:
                continue

            setattr(user, model_field, value)
            touched_fields.add(model_field)

        # Users can only be promoted to staff. Staff rights are never taken by OIDC.
        if config.options["groups_settings"]["make_users_staff"] and not user.is_staff:
            user.is_staff = True
            touched_fields.add("is_staff")

        groups_settings = config.options.get("groups_settings", {})
        groups = self._get_groups(claims, groups_settings.get("claim_mapping", []))

        # Assign superuser status to the user if the user is a member of at least one
        # specific group. Superuser status is explicitly removed if the user is not or
        # no longer member of at least one of these groups.
        if (
            superuser_group_names := groups_settings.get("superuser_group_names")
        ) and groups:
            # superuser is granted if there is overlap between the groups claim and the
            # specified superuser grup names
            make_superuser = bool(set(groups) & set(superuser_group_names))
            if make_superuser != user.is_superuser:
                user.is_superuser = make_superuser
                touched_fields.add("is_superuser")

        user.save(update_fields=touched_fields)

        self._set_user_groups(
            user,
            groups,
            default_group_names=groups_settings.get("default_groups", []),
            sync_missing_groups=groups_settings.get("sync", True),
            sync_groups_glob=groups_settings.get("sync_pattern", "*"),
        )

        return user

    def _get_groups(
        self, claims: JSONObject, groups_claim: ClaimPath
    ) -> list[str] | None:
        if not groups_claim:
            return

        # extract the specified claim
        groups: list[str] | str = glom(claims, Path(*groups_claim), default=missing)
        if groups is missing:
            logger.debug(
                "The configured groups claim '%s' was not found in the user info.",
                " > ".join(groups_claim),
            )
            groups = []

        # could be a string instead of a list of strings
        if isinstance(groups, str):
            groups = [groups]

        if not all(isinstance(name, str) for name in groups):
            logger.warning("Aborting! Groups is not a list of strings: %r", groups)
            return

        return groups

    def _set_user_groups(
        self,
        user: AbstractUser,
        groups: list[str] | None,
        default_group_names: list[str],
        sync_missing_groups: bool,
        sync_groups_glob: str,
    ) -> None:
        """
        Synchronize the groups from the config/claims and the model.
        """
        if groups is None:
            return

        # Incorporate the default groups into the desired state of groups.
        desired_group_names = set(default_group_names) | set(groups)

        # Update the user's group memberships, if required
        django_group_names = set(user.groups.values_list("name", flat=True))
        if set(desired_group_names) == django_group_names:
            return

        # Create missing groups if required
        existing_groups = get_groups_by_name(
            desired_group_names, sync_groups_glob, sync_missing_groups
        )

        # at this point, existing_groups is the full collection of groups that should be
        # set on the user model, because:
        #
        # * desired_group_names is equal to or a superset of the existing groups (superset
        #   if group synchronization is off or groups are excluded by the glob)
        # * the groups currently set on the user may contain groups not present in the
        #   desired group names, as the latter only reflects the default groups + groups in
        #   the claims
        user.groups.set(existing_groups)

    def get_schema(self) -> JSONObject:
        return ADMIN_OPTIONS_SCHEMA

    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        return admin_callback_view(request)
