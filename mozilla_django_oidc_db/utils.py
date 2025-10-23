import fnmatch
import logging
from collections.abc import Collection, Iterable
from copy import deepcopy

from django.contrib.auth.models import Group

import requests
from glom import Path, PathAccessError, assign, glom
from requests.utils import (
    _parse_content_type_header,  # pyright: ignore[reportAttributeAccessIssue]
)

from .models import OIDCClient
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
    Obfuscates the specified claims in the provided claims object.
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


def do_op_logout(config: OIDCClient, id_token: str) -> None:
    """
    Perform the logout with the OpenID Provider.

    Standard: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout

    .. warning:: Preferably, you should send the user to the configured logout endpoint
       so they can confirm the logout and any session cookies are cleared. If that is not
       possible, you can call this helper for server-to-server logout, but there are no
       guarantees this works for every possible OpenID Provider implementation. It has
       been tested with Keycloak, but the standard says nothing about server-to-server
       calls to log out a user.
    """
    provider = config.oidc_provider
    assert provider

    logout_endpoint = provider.oidc_op_logout_endpoint
    if not logout_endpoint:
        return

    response = requests.post(
        logout_endpoint,
        data={"id_token_hint": id_token},
        allow_redirects=False,
    )
    if not response.ok:
        logger.warning(
            "Failed to log out the user at the OpenID Provider. Status code: %s",
            response.status_code,
            extra={
                "response": response,
                "status_code": response.status_code,
            },
        )


def get_groups_by_name(
    group_names: Iterable[str], sync_groups_glob: str, sync_missing_groups: bool
) -> set[Group]:
    """
    Gets Django User groups by name.

    Optionally creates missing groups that match glob pattern.
    """

    existing_groups = set(Group.objects.filter(name__in=group_names))
    if not sync_missing_groups:
        return existing_groups

    existing_group_names = {group.name for group in existing_groups}
    filtered_names = fnmatch.filter(
        set(group_names) - existing_group_names, sync_groups_glob
    )

    groups_to_create = [Group(name=name) for name in filtered_names]
    if groups_to_create:
        # postgres sets the PK after bulk_create
        Group.objects.bulk_create(groups_to_create)
        existing_groups |= set(groups_to_create)
    return existing_groups
