from mozilla_django_oidc.middleware import SessionRefresh as _SessionRefresh
from mozilla_django_oidc.utils import import_from_settings

from .mixins import SoloConfigMixin
from .models import OpenIDConnectConfig


class SessionRefresh(SoloConfigMixin, _SessionRefresh):
    def process_request(self, request):
        config = OpenIDConnectConfig.get_solo()
        if not config.enabled:
            return

        return super().process_request(request)
