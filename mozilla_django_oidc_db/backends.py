from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import (
    AbstractBaseUser,
    AbstractUser,
    AnonymousUser,
)
from django.db import models
from django.http import HttpRequest

import requests
from mozilla_django_oidc.auth import OIDCAuthenticationBackend as BaseBackend

from .config import dynamic_setting, lookup_config
from .exceptions import MissingInitialisation
from .jwt import verify_and_decode_token
from .models import OIDCClient, UserInformationClaimsSources
from .plugins import AbstractUserOIDCPlugin, AnonymousUserOIDCPlugin
from .registry import register as registry
from .typing import JSONObject
from .utils import extract_content_type

logger = logging.getLogger(__name__)


missing = object()


class OIDCAuthenticationBackend(BaseBackend):
    """
    Custom backend modifying the upstream package behaviour.

    This backend looks up the configuration to use, which is set
    on the request by the init view. It does this by grabbing the state query parameter and looking
    in the session for this key. This key was set by the authentication request view.
    Scoped inside the state, there is the identifier of the configuration to use.

    The authenticate method saves the request on the backend instance.

    No configuration is loaded in :meth:`__init__` at all, instead we define properties
    to dynamically look this up. Django instantiates backends *a lot*, e.g. during
    permission checks. We only support the :meth:`authenticate` entrypoint like the
    upstream library.
    """

    request: HttpRequest | None = None  # set during the authenticate call
    config: OIDCClient | None = None  # set during the authenticate call

    # These should be functionaly equivalent to
    # :class:`mozilla_django_oidc.auth.OIDCAuthenticationBackend`.
    OIDC_OP_TOKEN_ENDPOINT = dynamic_setting[str]()
    OIDC_OP_USER_ENDPOINT = dynamic_setting[str]()
    OIDC_OP_JWKS_ENDPOINT = dynamic_setting[str | None](default=None)
    OIDC_RP_CLIENT_ID = dynamic_setting[str]()
    OIDC_RP_CLIENT_SECRET = dynamic_setting[str]()
    OIDC_RP_SIGN_ALGO = dynamic_setting[str](default="HS256")
    OIDC_RP_IDP_SIGN_KEY = dynamic_setting[str | None](default=None)

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
        UserModel = get_user_model()
        if TYPE_CHECKING:
            assert issubclass(UserModel, AbstractUser)
        self.UserModel = UserModel

    @override
    def get_settings(self, attr: str, *args: Any) -> Any:  # pyright: ignore[reportIncompatibleMethodOverride]
        """
        Override the upstream library get_settings.

        Upstream is django-settings based, and we store configuration in database
        records instead. We look up the configuration from the DB and check if the
        requested setting is defined there or not. If not, it is taken from the Django
        settings.
        """
        if not self.config:
            raise MissingInitialisation(
                "The configuration must be loaded from the authenticate entrypoint. It looks like "
                "you're trying to access configuration before this was called."
            )

        plugin = registry[self.config.identifier]
        plugin.validate_settings()

        return plugin.get_setting(attr, *args)

    def _check_candidate_backend(self) -> bool:
        return self.get_settings("enabled")

    # The method signature is checked by django when selecting a suitable backend. Our
    # signature is more strict than the upstream library. Check the upstream
    # `OIDCAuthenticationCallbackView` for the `auth.authenticate(**kwargs)` call if this
    # needs updating.
    @override
    def authenticate(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        request: HttpRequest | None,
        nonce: str | None = None,
        code_verifier: str | None = None,
    ) -> AnonymousUser | AbstractBaseUser | None:
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

        self.config = lookup_config(request)
        self.request = request

        # Check if this backend should be considered to authenticate the user.
        is_candidate = self._check_candidate_backend()
        if not is_candidate:
            return None

        # Allright, now try to actually authenticate the user.
        user = super().authenticate(request, nonce=nonce, code_verifier=code_verifier)

        # Store the config class identifier on the user, so that we can store this in the user's
        # session after they have been successfully authenticated (by listening to the `user_logged_in` signal)
        if user:
            user._oidcdb_config_identifier = self.config.identifier  # pyright: ignore[reportAttributeAccessIssue]

        return user

    @override
    def verify_claims(self, claims: JSONObject) -> bool:
        """Verify the provided claims to decide if authentication should be allowed."""
        assert claims, "Empty claims should have been blocked earlier"
        assert self.config

        plugin = registry[self.config.identifier]
        assert isinstance(plugin, AbstractUserOIDCPlugin)
        return plugin.verify_claims(claims)

    @override
    def get_userinfo(
        self, access_token: str, id_token: str, payload: JSONObject
    ) -> JSONObject:
        """
        Extract the user information, configurable whether to use the ID token or
        the userinfo endpoint for this
        """
        assert self.config

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
        assert self.config.oidc_provider
        user_response = requests.get(
            self.config.oidc_provider.oidc_op_user_endpoint,
            headers={
                "Authorization": f"Bearer {access_token}",
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
    def filter_users_by_claims(
        self, claims: JSONObject
    ) -> models.QuerySet[AbstractUser]:
        assert self.config
        plugin = registry[self.config.identifier]

        assert isinstance(plugin, AbstractUserOIDCPlugin)
        return plugin.filter_users_by_claims(claims)

    @override
    def create_user(self, claims: JSONObject) -> AbstractUser:
        """Create an authenticated user."""
        assert self.config
        plugin = registry[self.config.identifier]

        assert isinstance(plugin, AbstractUserOIDCPlugin)
        return plugin.create_user(claims)

    @override
    def update_user(self, user: AbstractUser, claims: JSONObject):
        assert self.config
        plugin = registry[self.config.identifier]

        assert isinstance(plugin, AbstractUserOIDCPlugin)
        return plugin.update_user(user, claims)

    @override
    def get_or_create_user(
        self, access_token: str, id_token: str, payload: JSONObject
    ) -> AnonymousUser | AbstractUser | None:
        """Get or create a user based on the tokens received."""
        assert self.config

        plugin = registry[self.config.identifier]
        assert isinstance(self.request, HttpRequest)

        # shortcut for "anonymous users" where the OIDC authentication *does* happen,
        # but no actual Django user instance is created.
        if isinstance(plugin, AnonymousUserOIDCPlugin):
            return plugin.get_or_create_user(
                access_token, id_token, payload, self.request
            )

        user = super().get_or_create_user(access_token, id_token, payload)
        if user is not None:
            assert isinstance(user, self.UserModel)
        return user
