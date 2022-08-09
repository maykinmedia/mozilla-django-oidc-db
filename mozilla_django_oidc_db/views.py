import logging

from django.contrib import admin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.urls import reverse_lazy
from django.views.generic import TemplateView

from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView as _OIDCAuthenticationRequestView,
)

from .mixins import SoloConfigMixin

logger = logging.getLogger(__name__)
OIDC_ERROR_SESSION_KEY = "oidc-error"


def get_exception_message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        # ValidationError can be raised as part of django.db.models.fields.Field.to_python,
        # and unfortunately we don't have any context about the exact field that raised
        # the exception.
        return exc.messages[0]
    return exc.args[0]


class OIDCCallbackView(OIDCAuthenticationCallbackView):
    """
    Intercept errors raised by the authentication backend and display them.
    """

    failure_url = reverse_lazy("admin-oidc-error")

    def get(self, request):
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
            request.session[OIDC_ERROR_SESSION_KEY] = exc_message
            return self.login_failure()
        else:
            if OIDC_ERROR_SESSION_KEY in request.session:
                del request.session[OIDC_ERROR_SESSION_KEY]
        return response


class AdminLoginFailure(TemplateView):
    """
    Template view in admin style to display OIDC login errors
    """

    template_name = "admin/oidc_failure.html"

    def dispatch(self, request, *args, **kwargs):
        if OIDC_ERROR_SESSION_KEY not in request.session:
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(admin.site.each_context(self.request))
        context["oidc_error"] = self.request.session[OIDC_ERROR_SESSION_KEY]
        return context


class OIDCAuthenticationRequestView(SoloConfigMixin, _OIDCAuthenticationRequestView):
    pass
