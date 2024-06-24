from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from .constants import CONFIG_CLASS_SESSION_KEY


@receiver([user_logged_in], dispatch_uid="oidcdb.set_config_class")
def set_oidcdb_config_class_on_session(sender, user, request, **kwargs):
    """
    Record the OIDC config class on the session, this is needed so the callback view
    can retrieve the config in case of a SessionRefresh flow
    """
    if hasattr(user, "_oidcdb_config_class"):
        request.session[CONFIG_CLASS_SESSION_KEY] = user._oidcdb_config_class
