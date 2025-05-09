from django.apps import AppConfig
from django.db.models.signals import post_migrate

from .signals import populate_oidc_config_models


class MozillaDjangoOidcDbConfig(AppConfig):
    name = "mozilla_django_oidc_db"
    default_auto_field = "django.db.models.AutoField"

    def ready(self) -> None:
        from . import checks  # noqa
        from . import plugins  # noqa
        from . import signals  # noqa

        post_migrate.connect(populate_oidc_config_models, sender=self)
