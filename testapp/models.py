from solo.models import SingletonModel

from mozilla_django_oidc_db.models import OpenIDConnectConfig, OpenIDConnectConfigBase
from mozilla_django_oidc_db.typing import DjangoView


class EmptyConfig(OpenIDConnectConfigBase):
    @property
    def oidc_authentication_callback_url(self):
        return "empty-config-callback"


class AnotherEmptyConfig(OpenIDConnectConfigBase):
    @property
    def oidc_authentication_callback_url(self):
        return "another-empty-config-callback"


class WrongConfigModel(SingletonModel):
    @property
    def oidc_op_authorization_endpoint(self):
        return "bad"

    @property
    def oidc_rp_client_id(self):
        return "also-bad"


class CustomCallbackViewConfig(OpenIDConnectConfig):
    class Meta:
        proxy = True

    def get_callback_view(self) -> DjangoView:
        from .views import CustomCallbackView

        return CustomCallbackView.as_view()
