from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import Literal, Protocol

from django.http import HttpRequest, HttpResponseBase

type EndpointFieldNames = Literal[
    "oidc_op_authorization_endpoint",
    "oidc_op_token_endpoint",
    "oidc_op_user_endpoint",
    "oidc_op_jwks_endpoint",
    "oidc_op_logout_endpoint",
]

type JSONPrimitive = str | int | float | bool | None
type JSONValue = JSONPrimitive | list[JSONValue] | JSONObject
type JSONObject = MutableMapping[str, JSONValue]

type ClaimPath = Sequence[str]

type GetParams = Mapping[str, str | bytes]


class DjangoView(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponseBase: ...
