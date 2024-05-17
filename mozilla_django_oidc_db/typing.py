from __future__ import annotations

from collections.abc import Sequence
from typing import TypeAlias

JSONPrimitive: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = "JSONPrimitive | list[JSONValue] | JSONObject"
JSONObject: TypeAlias = dict[str, JSONValue]

ClaimPath: TypeAlias = Sequence[str]
