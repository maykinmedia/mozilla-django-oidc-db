import logging
from collections.abc import Collection
from copy import deepcopy

import requests
from glom import Path, PathAccessError, assign, glom
from requests.utils import _parse_content_type_header  # type: ignore

from .models import OpenIDConnectConfigBase
from .typing import ClaimPath, JSONObject, JSONValue

logger = logging.getLogger(__name__)


def obfuscate_claim_value(value: JSONValue) -> JSONValue:
    """
    Obfuscates the value of a claim, so it can be logged safely

    If a dict of claims is supplied, all of the values will be obfuscated
    """
    if isinstance(value, dict):
        for k, v in value.items():
            value[k] = obfuscate_claim_value(v)
        return value
    else:
        value = str(value)
        threshold = int(len(value) * 0.75)
        return "".join([x if i > threshold else "*" for i, x in enumerate(value)])


def obfuscate_claims(
    claims: JSONObject, claims_to_obfuscate: Collection[ClaimPath]
) -> JSONObject:
    """
    Obfuscates the specified claims in the specified claims dict
    """
    copied_claims = deepcopy(claims)
    for claim_bits in claims_to_obfuscate:
        claim_path = Path(*claim_bits)
        try:
            claim_value = glom(copied_claims, claim_path)
        except PathAccessError:
            continue
        assign(copied_claims, claim_path, obfuscate_claim_value(claim_value))
    return copied_claims


def extract_content_type(ct_header: str) -> str:
    """
    Get the content type + parameters from content type header.

    This is internal API since we use a requests internal utility, which may be
    removed/modified at any time. However, this is a deliberate choices since I trust
    requests to have a correct implementation more than coming up with one myself.
    """
    content_type, _ = _parse_content_type_header(ct_header)
    # discard the params, we only want the content type itself
    return content_type


def do_op_logout(config: OpenIDConnectConfigBase, id_token: str) -> None:
    """
    Perform the logout with the OpenID Provider.

    Standard: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
    """
    logout_endpoint = config.oidc_op_logout_endpoint
    if not logout_endpoint:
        return

    response = requests.post(logout_endpoint, data={"id_token_hint": id_token})
    if not response.ok:
        logger.warning(
            "Failed to log out the user at the OpenID Provider. Status code: %s",
            response.status_code,
            extra={
                "response": response,
                "status_code": response.status_code,
            },
        )
