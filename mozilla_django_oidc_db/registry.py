from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from mozilla_django_oidc_db.plugins import OIDCBasePlugin

from .constants import UNIQUE_PLUGIN_ID_MAX_LENGTH


class OIDCRegistry:
    _registry: dict

    def __init__(self):
        self._registry = {}

    def __call__(
        self, unique_identifier: str
    ) -> Callable[[type["OIDCBasePlugin"]], type["OIDCBasePlugin"]]:

        if len(unique_identifier) > UNIQUE_PLUGIN_ID_MAX_LENGTH:
            raise ValueError(
                f"The unique identifier '{unique_identifier}' is longer than "
                f"{UNIQUE_PLUGIN_ID_MAX_LENGTH} characters."
            )

        def decorator(plugin_cls: type["OIDCBasePlugin"]) -> type["OIDCBasePlugin"]:
            if unique_identifier in self._registry:
                raise ValueError(
                    f"The unique identifier '{unique_identifier}' is already present "
                    "in the registry."
                )

            plugin = plugin_cls(identifier=unique_identifier)
            self.check_plugin(plugin)
            self._registry[unique_identifier] = plugin
            return plugin_cls

        return decorator

    def items(self):
        return iter(self._registry.items())

    def check_plugin(self, plugin: "OIDCBasePlugin"):
        # validation hook
        pass

    def __getitem__(self, key: str) -> "OIDCBasePlugin":
        return self._registry[key]


# Sentinel to provide the registry. You can easily instantiate another
# :class:`Registry` object to use as dependency injection in tests.
register = OIDCRegistry()
