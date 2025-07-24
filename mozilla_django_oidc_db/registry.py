from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Iterable

from .constants import UNIQUE_PLUGIN_ID_MAX_LENGTH

if TYPE_CHECKING:
    from .plugins import OIDCPlugin


class OIDCRegistry:
    _registry: dict[str, OIDCPlugin]

    def __init__(self):
        self._registry = {}

    def __call__(
        self, unique_identifier: str
    ) -> Callable[[type[OIDCPlugin]], type[OIDCPlugin]]:

        if len(unique_identifier) > UNIQUE_PLUGIN_ID_MAX_LENGTH:
            raise ValueError(
                f"The unique identifier '{unique_identifier}' is longer than "
                f"{UNIQUE_PLUGIN_ID_MAX_LENGTH} characters."
            )

        def decorator(plugin_cls: type[OIDCPlugin]) -> type[OIDCPlugin]:
            if unique_identifier in self._registry:
                raise ValueError(
                    f"The unique identifier '{unique_identifier}' is already present "
                    "in the registry."
                )

            plugin = plugin_cls(identifier=unique_identifier)
            self._registry[unique_identifier] = plugin
            return plugin_cls

        return decorator

    def items(self) -> Iterable[tuple[str, OIDCPlugin]]:
        return self._registry.items()

    def __getitem__(self, key: str) -> OIDCPlugin:
        return self._registry[key]


# Sentinel to provide the registry. You can easily instantiate another
# :class:`Registry` object to use as dependency injection in tests.
register = OIDCRegistry()
