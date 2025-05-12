from django.apps import AppConfig


class TestappConfig(AppConfig):
    name = "testapp"

    def ready(self) -> None:
        from . import plugins  # noqa
