"""
Support for user info JWT verification and decoding.

The bulk of the implementation is taken from mozilla-django-oidc where the access token
is processed, but adapted for non-hardcoded/configured parameters.

In the case of Keycloak for example, the token signing algorithm is configured on the
server and can change on a whim.
"""

import json

from django.core.exceptions import SuspiciousOperation
from django.utils.encoding import smart_bytes

from josepy.jwk import JWK
from josepy.jws import JWS

from .typing import JSONObject


def verify_and_decode_token(token: bytes, key) -> JSONObject:
    """
    Verify that the token was not tampered with and if okay, return the payload.

    This is mostly taken from
    :meth:`mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws`.
    """

    jws = JWS.from_compact(token)

    # validate the signing algorithm
    if (alg := jws.signature.combined.alg) is None:
        raise SuspiciousOperation("No alg value found in header")

    # one of the most common implementation weaknesses -> attacker can supply 'none'
    # algorithm
    if alg.name == "none":
        raise SuspiciousOperation("'none' for alg value is not allowed")

    # process key parameter which was/may have been loaded from keys endpoint. The
    # string variant is unknown - this code is replicated from upstream
    # mozilla-django-oidc key verification.
    match key:
        case str():
            jwk = JWK.load(smart_bytes(key))
        case _:
            jwk = JWK.from_json(key)
            # address some missing upstream Self type declarations
            assert isinstance(jwk, JWK)

    if not jws.verify(jwk):
        raise SuspiciousOperation("JWS token verification failed.")

    return json.loads(jws.payload.decode("utf-8"))
