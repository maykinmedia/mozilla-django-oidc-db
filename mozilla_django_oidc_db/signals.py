from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from .constants import CONFIG_IDENTIFIER_SESSION_KEY
from .registry import register as registry


@receiver([user_logged_in], dispatch_uid="oidcdb.set_config_identifier")
def set_oidcdb_config_identifier_on_session(sender, user, request, **kwargs):
    """
    Record the OIDC config identifier on the session, this is needed so the callback view
    can retrieve the config in case of a SessionRefresh flow.
    """
    if hasattr(user, "_oidcdb_config_identifier"):
        request.session[CONFIG_IDENTIFIER_SESSION_KEY] = user._oidcdb_config_identifier


def populate_oidc_config_models(sender, **kwargs) -> None:
    """
    See which OIDC plugins are registered and make sure that the corresponding configuration model exists in the
    database.
    """
    if not (apps := kwargs.get("apps")):
        return

    OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")

    for unique_identifier in registry:
        OIDCClient.objects.get_or_create(identifier=unique_identifier)
