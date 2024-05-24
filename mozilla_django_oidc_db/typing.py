from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeAlias

from django.http import HttpRequest, HttpResponseBase

JSONPrimitive: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = "JSONPrimitive | list[JSONValue] | JSONObject"
JSONObject: TypeAlias = dict[str, JSONValue]

ClaimPath: TypeAlias = Sequence[str]


class DjangoView(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponseBase: ...
