from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, TypeAlias, Union

from django.http import HttpRequest, HttpResponseBase

if TYPE_CHECKING:
    from django.contrib.auth.models import (
        AbstractBaseUser,
        AnonymousUser,
    )

JSONPrimitive: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = "JSONPrimitive | list[JSONValue] | JSONObject"
JSONObject: TypeAlias = dict[str, JSONValue]

ClaimPath: TypeAlias = Sequence[str]

AnyUser: TypeAlias = Union["AnonymousUser", "AbstractBaseUser"]


class DjangoView(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponseBase: ...
