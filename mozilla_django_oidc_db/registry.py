from __future__ import annotations

from collections.abc import Callable, Iterable, MutableMapping
from typing import TYPE_CHECKING

from .constants import UNIQUE_PLUGIN_ID_MAX_LENGTH

if TYPE_CHECKING:
    from .plugins import BaseOIDCPlugin


class OIDCRegistry[T: type[BaseOIDCPlugin]]:
    _registry: MutableMapping[str, T]

    def __init__(self):
        self._registry = {}

    def __call__(self, unique_identifier: str) -> Callable[[T], T]:
        if len(unique_identifier) > UNIQUE_PLUGIN_ID_MAX_LENGTH:
            raise ValueError(
                f"The unique identifier '{unique_identifier}' is longer than "
                f"{UNIQUE_PLUGIN_ID_MAX_LENGTH} characters."
            )

        def decorator(plugin_cls: T) -> T:
            if unique_identifier in self._registry:
                raise ValueError(
                    f"The unique identifier '{unique_identifier}' is already present "
                    "in the registry."
                )

            plugin = plugin_cls(identifier=unique_identifier)
            self._registry[unique_identifier] = plugin
            return plugin_cls

        return decorator

    def items(self) -> Iterable[tuple[str, T]]:
        return self._registry.items()

    def __iter__(self):
        return iter(self._registry)

    def __getitem__(self, key: str) -> T:
        return self._registry[key]


# Sentinel to provide the registry. You can easily instantiate another
# :class:`Registry` object to use as dependency injection in tests.
register = OIDCRegistry()
