from __future__ import annotations

import logging
from collections.abc import Collection
from typing import Any, TypeAlias, cast

from django.contrib.auth import get_user_model
from django.contrib.auth.models import (
    AbstractBaseUser,
    AbstractUser,
    AnonymousUser,
    Group,
)
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest

import requests
from glom import Path, glom
from mozilla_django_oidc.auth import OIDCAuthenticationBackend as BaseBackend
from typing_extensions import override

from .config import dynamic_setting, get_setting_from_config, lookup_config
from .exceptions import MissingIdentifierClaim
from .jwt import verify_and_decode_token
from .models import OpenIDConnectConfigBase, UserInformationClaimsSources
from .typing import ClaimPath, JSONObject
from .utils import extract_content_type, get_groups_by_name, obfuscate_claims

logger = logging.getLogger(__name__)

AnyUser: TypeAlias = AnonymousUser | AbstractBaseUser

missing = object()


class OIDCAuthenticationBackend(BaseBackend):
    """
    Custom backend modifying the upstream package behaviour.

    This backend is meant to look up the configuration (class) to use, which is set
    in the session by the init view. It does this by grabbing the state parameter from
    the GET params to look up the state set in the authentication request view. The
    specified configuration parameters are then loaded and applied.

    No configuration is loaded in :meth:`__init__` at all, instead we define properties
    to dynamically look this up. Django instantiates backends *a lot*, e.g. during
    permission checks. We only support the :meth:`authenticate` entrypoint like the
    upstream library.
    """

    request: HttpRequest | None = None  # set during the authenticate call

    config_class: type[OpenIDConnectConfigBase]

    # These should be functionaly equivalent to
    # :class:`mozilla_django_oidc.auth.OIDCAuthenticationBackend`.
    OIDC_OP_TOKEN_ENDPOINT = dynamic_setting[str]()
    OIDC_OP_USER_ENDPOINT = dynamic_setting[str]()
    OIDC_OP_JWKS_ENDPOINT = dynamic_setting[str | None](default=None)
    OIDC_RP_CLIENT_ID = dynamic_setting[str]()
    OIDC_RP_CLIENT_SECRET = dynamic_setting[str]()
    OIDC_RP_SIGN_ALGO = dynamic_setting[str](default="HS256")
    OIDC_RP_IDP_SIGN_KEY = dynamic_setting[str | None](default=None)

    # Custom config/settings from our own models. These map to model fields or
    # properties on the OpenIDConnectConfigBase model. The settings with defaults can
    # be provided by subclasses of OpenIDConnectConfigBase or plain old Django settings.
    OIDCDB_SENSITIVE_CLAIMS = dynamic_setting[Collection[ClaimPath]]()
    OIDCDB_USERNAME_CLAIM = dynamic_setting[ClaimPath]()
    OIDCDB_USERINFO_CLAIMS_SOURCE = dynamic_setting[UserInformationClaimsSources](
        default=UserInformationClaimsSources.userinfo_endpoint
    )
    OIDCDB_USERNAME_CASE_SENSITIVE = dynamic_setting[bool](default=True)
    OIDCDB_CLAIM_MAPPING = dynamic_setting[dict[str, ClaimPath]](default={})
    OIDCDB_GROUPS_CLAIM = dynamic_setting[ClaimPath](default=[])
    OIDCDB_DEFAULT_GROUPS = dynamic_setting[Collection[str]](default=[])
    OIDCDB_SYNC_MISSING_GROUPS = dynamic_setting[bool](default=True)
    OIDCDB_SYNC_GROUPS_GLOB_PATTERN = dynamic_setting[str](default="*")
    OIDCDB_MAKE_USERS_STAFF = dynamic_setting[bool](default=False)
    OIDCDB_SUPERUSER_GROUP_NAMES = dynamic_setting[Collection[str]](default=[])

    @override
    def __init__(self, *args, **kwargs) -> None:
        # Deliberately empty, we discard all initialization from the parent class which
        # requires a config_class to be set. Even if we set it (declaratively), this is
        # not viable because it performs DB/cache IO to look up the config instance,
        # which would happen as well when Django goes through the auth backends for
        # permission checks.
        #
        # See https://github.com/maykinmedia/mozilla-django-oidc-db/issues/30

        # django-stubs returns AbstractBaseUser, but we depend on properties of
        # AbstractUser.
        self.UserModel = cast(AbstractUser, get_user_model())

    @override
    def get_settings(self, attr: str, *args: Any) -> Any:  # type: ignore
        """
        Override the upstream library get_settings.

        Upstream is django-settings based, and we store configuration in database
        records instead. We look up the configuration from the DB and check if the
        requested setting is defined there or not. If not, it is taken from the Django
        settings.
        """
        assert hasattr(self, "config_class"), (
            "The config must be loaded from the authenticate entrypoint. It looks like "
            "you're trying to access configuration before this was called."
        )
        if (config := getattr(self, "_config", None)) is None:
            # django-solo and type checking is challenging, but a new release is on the
            # way and should fix that :fingers_crossed:
            config = cast(OpenIDConnectConfigBase, self.config_class.get_solo())
            self._config = config
            self._validate_settings()
        return get_setting_from_config(config, attr, *args)

    def _validate_settings(self):
        # Equivalent of checks in upstream __init__ method
        if (
            self.OIDC_RP_SIGN_ALGO.startswith("RS")
            or self.OIDC_RP_SIGN_ALGO.startswith("ES")
        ) and (
            self.OIDC_RP_IDP_SIGN_KEY is None and self.OIDC_OP_JWKS_ENDPOINT is None
        ):
            msg = "{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured."
            raise ImproperlyConfigured(msg.format(self.OIDC_RP_SIGN_ALGO))

    def _check_candidate_backend(self) -> bool:
        return self.get_settings("enabled")

    # The method signature is checked by django when selecting a suitable backend. Our
    # signature is more strict than the upstream library. Check the upstream
    # `OIDCAuthenticationCallbackView` for the `auth.authenticate(**kwargs)` call if this
    # needs updating.
    @override
    def authenticate(  # type: ignore
        self,
        request: HttpRequest | None,
        nonce: str | None = None,
        code_verifier: str | None = None,
    ) -> AnyUser | None:
        """
        Authenticate the user with OIDC *iff* the conditions are met.

        Return ``None`` to skip to the next backend, raise
        :class:`django.core.exceptions.PermissionDenied` to stop in our tracks. Return
        a user object (real or anonymous) to signify success.
        """
        # if we don't get a request, we can't check anything, so skip to the next
        # backend. We need to grab the state and code from request.GET for OIDC.
        if request is None:
            return None

        # Load the config to apply and check if this backend should be considered to
        # authenticate the user.
        self.config_class = lookup_config(request)
        is_candidate = self._check_candidate_backend()
        if not is_candidate:
            return None

        # Allright, now try to actually authenticate the user.
        user = super().authenticate(request, nonce=nonce, code_verifier=code_verifier)

        # Store the config class name on the user, so that we can store this in the user's
        # session after they have been successfully authenticated (by listening to the `user_logged_in` signal)
        if user:
            options = self.config_class._meta
            user._oidcdb_config_class = f"{options.app_label}.{options.object_name}"  # type: ignore

        return user

    def _extract_username(
        self, claims: JSONObject, *, raise_on_empty: bool = False
    ) -> str:
        """
        Given the claims and the dynamic config, extract the username value.
        """
        claim_bits = self.OIDCDB_USERNAME_CLAIM
        unique_id = glom(claims, Path(*claim_bits), default="")
        if raise_on_empty and not unique_id:
            raise MissingIdentifierClaim(claim_bits=claim_bits)
        return unique_id

    @override
    def verify_claims(self, claims: JSONObject) -> bool:
        """Verify the provided claims to decide if authentication should be allowed."""
        assert claims, "Empty claims should have been blocked earlier"

        obfuscated_claims = obfuscate_claims(claims, self.OIDCDB_SENSITIVE_CLAIMS)

        logger.debug("OIDC claims received: %s", obfuscated_claims)

        # check if we have an identifier
        try:
            self._extract_username(claims, raise_on_empty=True)
        except MissingIdentifierClaim as exc:
            logger.error(
                "'%s' not in OIDC claims, cannot proceed with authentication",
                " > ".join(exc.claim_bits),
                exc_info=exc,
            )
            return False
        return True

    @override
    def get_userinfo(
        self, access_token: str, id_token: str, payload: JSONObject
    ) -> JSONObject:
        """
        Extract the user information, configurable whether to use the ID token or
        the userinfo endpoint for this
        """
        if self.OIDCDB_USERINFO_CLAIMS_SOURCE == UserInformationClaimsSources.id_token:
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

    @override
    def filter_users_by_claims(self, claims: JSONObject):
        """Return all users matching the specified subject."""
        username = self._extract_username(claims)
        assert username, (
            "A username must be provided. Did you forget to check empty usernames "
            "in the claim verification?"
        )

        lookup = self.UserModel.USERNAME_FIELD
        if not self.OIDCDB_USERNAME_CASE_SENSITIVE:
            lookup += "__iexact"

        return self.UserModel.objects.filter(**{lookup: username})

    @override
    def create_user(self, claims: JSONObject) -> AnyUser:
        """Return object for a newly created user account."""
        username = self._extract_username(claims)
        logger.debug("Creating OIDC user: %s", username)

        user = self.UserModel.objects.create_user(
            **{self.UserModel.USERNAME_FIELD: username}
        )
        self.update_user(user, claims)
        return user

    @override
    def update_user(self, user: AbstractUser, claims: JSONObject):
        """
        Update existing user with new claims, if necessary save, and return user

        This method checks dynamic settings, which are provided by our
        :class:`~mozilla_django_oidc_db.models.OpenIDConnectConfig` model. If the
        respective fields do not exist on the config model being used, you must make
        sure they exist as Django settings.
        """
        logger.debug("Updating OIDC user %s", user)

        touched_fields: set[str] = set()

        for model_field, claim_bits in self.OIDCDB_CLAIM_MAPPING.items():
            value = glom(claims, Path(*claim_bits), default=missing)
            if value is missing:
                continue
            setattr(user, model_field, value)
            touched_fields.add(model_field)

        # Users can only be promoted to staff. Staff rights are never taken by OIDC.
        if self.OIDCDB_MAKE_USERS_STAFF and not user.is_staff:
            user.is_staff = True
            touched_fields.add("is_staff")

        groups = _get_groups(claims, self.OIDCDB_GROUPS_CLAIM)

        # Assign superuser status to the user if the user is a member of at least one
        # specific group. Superuser status is explicitly removed if the user is not or
        # no longer member of at least one of these groups.
        if self.OIDCDB_SUPERUSER_GROUP_NAMES and groups:
            # superuser is granted if there is overlap between the groups claim and the
            # specified superuser grup names
            make_superuser = bool(set(groups) & set(self.OIDCDB_SUPERUSER_GROUP_NAMES))
            if make_superuser != user.is_superuser:
                user.is_superuser = make_superuser
                touched_fields.add("is_superuser")

        user.save(update_fields=touched_fields)

        _set_user_groups(
            user,
            groups,
            default_group_names=self.OIDCDB_DEFAULT_GROUPS,
            sync_missing_groups=self.OIDCDB_SYNC_MISSING_GROUPS,
            sync_groups_glob=self.OIDCDB_SYNC_GROUPS_GLOB_PATTERN,
        )

        return user


def _get_groups(claims: JSONObject, groups_claim: ClaimPath) -> list[str] | None:
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
    user: AbstractUser,
    groups: list[str] | None,
    default_group_names: Collection[str],
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
