from mozilla_django_oidc.middleware import SessionRefresh as _SessionRefresh

from .mixins import GetAttributeMixin, SoloConfigMixin


class SessionRefresh(GetAttributeMixin, SoloConfigMixin, _SessionRefresh):
    def __init__(self, get_response):
        # `super().__init__` is not called here, because this attempts to initialize
        # the settings (which should be retrieved from `OpenIDConnectConfig`).

        # The retrieval of these settings has been moved to runtime (`__getattribute__` from the `GetAttributeMixin`)
        super(_SessionRefresh, self).__init__(get_response=get_response)

    def process_request(self, request):
        # Initialize to retrieve the settings from config model
        super().__init__(self.get_response)

        self.refresh_config()
        if not self.config.enabled:
            return

        return super().process_request(request)
