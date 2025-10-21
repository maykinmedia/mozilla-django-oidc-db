import logging
from typing import Any
from urllib.parse import parse_qs, urlsplit

from django.contrib import admin
from django.core.exceptions import DisallowedRedirect, PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponseBase, HttpResponseRedirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import TemplateView

import requests
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView as BaseOIDCCallbackView,
    OIDCAuthenticationRequestView as BaseOIDCAuthRequestInitView,
)

from .config import get_setting_from_config, lookup_config, store_config
from .constants import OIDC_ADMIN_CONFIG_IDENTIFIER
from .exceptions import OIDCProviderOutage
from .models import OIDCClient
from .registry import register as registry
from .typing import GetParams

logger = logging.getLogger(__name__)

_OIDC_ERROR_SESSION_KEY = "oidc-error"
"""
Session key where to store authentication error messages.

During the callback flow, if any errors are encountered, they are stored in the session
under this key so that :class:`AdminLoginFailure` can read and display them to the
end-user.
"""

_RETURN_URL_SESSION_KEY = "oidc-db_redirect_next"
"""
Session key for the "next" URL to redirect the user to.

This is the equivalent of the "oidc_login_next" session key from mozilla_django_oidc,
which we deliberately do not rely on as their usage may change and it is private API.

In some situations the value of this session key needs to be used as base to properly
display problems (used in the ``failure_url`` flow of the callback view).
"""


def get_exception_message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        # ValidationError can be raised as part of django.db.models.fields.Field.to_python,
        # and unfortunately we don't have any context about the exact field that raised
        # the exception.
        return exc.messages[0]
    return exc.args[0]


class OIDCCallbackView(View):
    """
    Route to the appropriate callback request handler.

    When a callback request is received, the state contains information about the
    configuration model to use. A particular configuration may require
    certain view behaviour. This view acts as a centralized entrypoint so that there
    is only a single callback endpoint required. It ensures that the configuration
    is extracted from the request.
    """

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponseBase:
        """
        Extract the state from the request parameters and persist it.

        The state is extracted so that it's available for the authentication backend(s)
        and the downstream views.
        """
        store_config(request)
        configuration = lookup_config(request)
        plugin = registry[configuration.identifier]
        return plugin.handle_callback(request)


class OIDCAuthenticationCallbackView(BaseOIDCCallbackView):
    """
    Base callback view that retrieves the settings from the config object.
    """

    def get_settings(self, attr: str, *args: Any) -> Any:  # type: ignore
        """
        Look up the request setting from the database config.

        For the duration of the request, the configuration instance is cached on the
        view.
        """
        if (configuration := getattr(self, "_config", None)) is None:
            configuration = lookup_config(self.request)
            self._config = configuration
        return get_setting_from_config(configuration, attr, *args)


class AdminCallbackView(OIDCAuthenticationCallbackView):
    """
    Intercept errors raised by the authentication backend and display them.
    """

    @property
    def failure_url(self):
        return reverse("admin-oidc-error")

    def get(self, request: HttpRequest, *args, **kwargs):
        try:
            # ensure errors don't lead to half-created users
            with transaction.atomic():
                response = super().get(request)
        except (IntegrityError, ValidationError) as exc:
            logger.exception(
                "Something went wrong while attempting to authenticate via OIDC",
                exc_info=exc,
            )
            exc_message = get_exception_message(exc)
            request.session[_OIDC_ERROR_SESSION_KEY] = exc_message
            return self.login_failure()
        else:
            if _OIDC_ERROR_SESSION_KEY in request.session:
                del request.session[_OIDC_ERROR_SESSION_KEY]
        return response


default_callback_view = OIDCAuthenticationCallbackView.as_view()
admin_callback_view = AdminCallbackView.as_view()


class AdminLoginFailure(TemplateView):
    """
    Template view in admin style to display OIDC login errors
    """

    template_name = "admin/oidc_failure.html"

    def dispatch(self, request, *args, **kwargs):
        if _OIDC_ERROR_SESSION_KEY not in request.session:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(admin.site.each_context(self.request))
        context["oidc_error"] = self.request.session[_OIDC_ERROR_SESSION_KEY]
        return context


class OIDCAuthenticationRequestInitView(BaseOIDCAuthRequestInitView):
    """
    A 'view' to start an OIDC authentication flow.

    This view class is parametrized with the identifier of the config model, so that
    the specific configuration can be retrieved and settings such as the identity provider endpoint
    to redirect the user to can be obtained.

    This view is not necessarily meant to be exposed directly via a URL pattern, but
    rather specific views are to be created from it, e.g.:

    .. code-block:: python

        >>> digid_init = OIDCAuthenticationRequestInitView.as_view(identifier="digid-oidc")
        >>> redirect_response = digid_init(request)
        # Redirect to some keycloak instance, for example.

    The ``__init__`` method of the Django ``View`` will add attributes to the view for
    any args/kwargs passed during init. So the view will have an attribute ``identifier``.
    Note that it only does it for attributes that are already defined as class attributes.

    These concrete views are intended to be wrapped by your own views so that you can
    supply the ``return_url`` parameter:

    .. code-block:: python

        def my_digid_login(request):
            return digid_init(request, return_url=request.GET["next"])

    Compared to :class:`mozilla_django_oidc.views.OIDCAuthenticationRequestView`, some
    extra actions are performed:

    * Any Keycloak IdP hint is added, if configured
    * The ``return_url`` is validated against unsafe redirects
    * The availability of the identity provider endpoint can be checked, if it's not
      available, the :class:`mozilla_django_oidc_db.exceptions.OIDCProviderOutage`
      exception is raised. Note that your own code needs to handle this appropriately!
    """

    identifier: str = ""
    """
    The identifier of the config model to get the settings from.

    Specify this as a kwarg in the ``as_view(identifier=...)`` class method.
    """

    allow_next_from_query: bool = True
    """
    Specify if the url-to-redirect-to may be provided as a query string parameter.

    For OIDC auth in the admin, you want to enable this to make URLs like
    ``/oidc/authenticate/?next=/admin/`` work as expected. For more advanced flows,
    you may want explicit control over this URL via your own wrapper view:

    .. code-block:: python

        digid_init = OIDCAuthenticationRequestInitView.as_view(
            identifier="config-identifier", allow_next_from_query=False
        )

        def my_digid_login(request):
            return digid_init(request, return_url="/some-fixed-url")
    """

    def get(
        self, request: HttpRequest, return_url: str = "", *args, **kwargs
    ) -> HttpResponseRedirect:
        if not self.allow_next_from_query:
            self._validate_return_url(request, return_url=return_url)

        if self.get_settings("check_op_availability", False):
            self.check_idp_availability()

        response = super().get(request, *args, **kwargs)

        # update the return_url value with what the upstream library extracted from the
        # GET query parameters.
        if self.allow_next_from_query:
            return_url = request.session["oidc_login_next"]

        # We add our own key to keep track of the redirect URL. In the case of
        # authentication failure (or canceled logins), the session is cleared by the
        # upstream library, so in the callback view we store this URL so that we know
        # where to redirect with the error information.
        request.session[_RETURN_URL_SESSION_KEY] = return_url

        # mozilla-django-oidc grabs this from request.GET and since that is not mutable,
        # it's easiest to just override the session key with the correct value.
        request.session["oidc_login_next"] = return_url

        # Store the config identifier to use in the state. We can not simply pass this as
        # a querystring parameter appended to redirect_uri, as these are likely to be
        # strictly validated. We must grab the state from the redirect Location.
        # This config reference is later used in the authentication callback view and
        # the authentication backend.
        query = parse_qs(urlsplit(response.url).query)
        state_params: list[str] = query["state"]
        assert len(state_params) == 1, "Expected only a single state parameter"
        state_key = state_params[0]

        # update the state. the parent class caused the session to be marked as modified,
        # so django's middleware will take care of persisting this to the session backend.
        state = request.session["oidc_states"][state_key]
        state["config_identifier"] = self.identifier

        return response

    def get_settings(self, attr: str, *args: Any) -> Any:  # type: ignore
        """
        Look up the request setting from the database config.

        For the duration of the request, the configuration instance is cached on the
        view.
        """
        if (config := getattr(self, "_config", None)) is None:
            config = OIDCClient.objects.get(identifier=self.identifier)
            self._config = config
        return get_setting_from_config(config, attr, *args)

    @staticmethod
    def _validate_return_url(request: HttpRequest, return_url: str) -> None:
        """
        Validate that the return URL meets the requirements.

        1. A non-empty value needs to be provided.
        2. The URL must be a safe redirect - only internal redirects are allowed.
        """
        if not return_url:
            raise ValueError("You must pass a return URL")

        url_is_safe = url_has_allowed_host_and_scheme(
            url=return_url,
            allowed_hosts=request.get_host(),
            require_https=request.is_secure(),
        )
        if not url_is_safe:
            raise DisallowedRedirect(f"Can't redirect to '{return_url}'")

    def check_idp_availability(self) -> None:
        """
        Hook for subclasses.

        Raise :class:`OIDCProviderOutage` if the Identity Provider is not available,
        which your application code needs to handle.

        The default implementation checks if the endpoint has a status code < 401.
        """
        endpoint = self.get_settings("OIDC_OP_AUTH_ENDPOINT")
        try:
            # Verify that the identity provider endpoint can be reached. This is where
            # the user ultimately gets redirected to.
            #
            # 5 seconds wait time is probably already too long for a good user
            # experience, but we don't want to be *too* aggressive.
            response = requests.get(endpoint, timeout=5.0)
            # some IDPs have been observed to return HTTP 400 because of the missing
            # query params
            if response.status_code > 400:
                response.raise_for_status()
        except requests.RequestException as exc:
            logger.info(
                "OIDC provider endpoint '%s' could not be retrieved",
                endpoint,
                exc_info=exc,
            )
            raise OIDCProviderOutage("Identity provider appears to be down.") from exc

    def get_extra_params(self, request: HttpRequest) -> GetParams:
        """
        Add a keycloak identity provider hint if configured.
        """
        extra: GetParams = super().get_extra_params(request)

        if kc_idp_hint := self.get_settings("OIDC_KEYCLOAK_IDP_HINT", ""):
            extra = {**extra, "kc_idp_hint": kc_idp_hint}

        plugin = registry[self.identifier]
        return plugin.get_extra_params(request, extra)


class OIDCAuthenticationRequestView(OIDCAuthenticationRequestInitView):
    """
    Start an OIDC authentication flow.

    This view is pre-configured to use the OIDC configuration included in this library,
    intended for admin authentication. Enable it in your Django settings with:

    .. code-block:: python

        OIDC_AUTHENTICATE_CLASS = (
            "mozilla_django_oidc_db.views.OIDCAuthenticationRequestView"
        )
    """

    identifier = OIDC_ADMIN_CONFIG_IDENTIFIER
    allow_next_from_query = True
