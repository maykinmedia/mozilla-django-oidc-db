from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.typing import JSONObject


class MockBackend(OIDCAuthenticationBackend):
    """
    Auth backend that mocks the actual code -> token exchange and verification.
    """

    def __init__(self, claims: JSONObject):
        super().__init__()
        self._claims = claims

    def get_token(self, payload):
        return {
            "id_token": "-mock-id-token-",
            "access_token": "-mock-access-token-",
        }

    def verify_token(self, token: str, **kwargs) -> JSONObject:
        return self._claims
