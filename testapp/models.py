from solo.models import SingletonModel

from mozilla_django_oidc_db.models import OpenIDConnectConfigBase


class EmptyConfig(OpenIDConnectConfigBase):
    pass


class WrongConfigModel(SingletonModel):

    @property
    def oidc_op_authorization_endpoint(self):
        return "bad"

    @property
    def oidc_rp_client_id(self):
        return "also-bad"
