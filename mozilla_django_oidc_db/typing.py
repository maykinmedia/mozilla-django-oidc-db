from __future__ import annotations

from collections.abc import MutableMapping, Sequence
from typing import Protocol

from django.http import HttpRequest, HttpResponseBase

type JSONPrimitive = str | int | float | bool | None
type JSONValue = JSONPrimitive | list[JSONValue] | JSONObject
type JSONObject = MutableMapping[str, JSONValue]

type ClaimPath = Sequence[str]


class DjangoView(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponseBase: ...
