import logging

from mozilla_django_oidc.auth import (
    OIDCAuthenticationBackend as _OIDCAuthenticationBackend,
)

from .mixins import SoloConfigMixin
from .models import OpenIDConnectConfig

logger = logging.getLogger(__name__)


class OIDCAuthenticationBackend(SoloConfigMixin, _OIDCAuthenticationBackend):
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
