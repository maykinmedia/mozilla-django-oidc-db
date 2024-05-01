# Generated by Django 4.2.9 on 2024-05-01 16:10

from django.conf import settings
from django.core.cache import caches
from django.db import migrations, models, transaction

import mozilla_django_oidc_db.fields
import mozilla_django_oidc_db.models


def flush_cache():
    if not (cache_name := getattr(settings, "SOLO_CACHE", "")):
        return
    caches[cache_name].clear()


def forward(config) -> None:
    config.new_username_claim = config.username_claim.split(".")
    config.new_groups_claim = config.groups_claim.split(".")
    config.claim_mapping = {
        key: value.split(".") for key, value in config.claim_mapping.items()
    }


def reverse(config) -> None:
    config.username_claim = ".".join(config.new_username_claim)
    config.groups_claim = ".".join(config.new_groups_claim)
    config.claim_mapping = {
        key: ".".join(value) for key, value in config.claim_mapping.items()
    }


def action_factory(transformer):
    def _run_python_action(apps, _) -> None:
        OpenIDConnectConfig = apps.get_model(
            "mozilla_django_oidc_db", "OpenIDConnectConfig"
        )

        # Solo model, so there's only ever one instance
        config = OpenIDConnectConfig.objects.first()
        if config is None:
            return

        transformer(config)

        config.save()
        transaction.on_commit(flush_cache)

    return _run_python_action


copy_forward = action_factory(transformer=forward)
copy_reverse = action_factory(transformer=reverse)


class Migration(migrations.Migration):

    dependencies = [
        ("mozilla_django_oidc_db", "0001_initial_to_v015"),
    ]

    operations = [
        migrations.AddField(
            model_name="openidconnectconfig",
            name="new_groups_claim",
            field=mozilla_django_oidc_db.fields.ClaimField(
                base_field=models.CharField(
                    max_length=50, verbose_name="claim path segment"
                ),
                blank=True,
                default=mozilla_django_oidc_db.models.get_default_groups_claim,
                help_text="The name of the OIDC claim that holds the values to map to local user groups.",
                size=None,
                verbose_name="groups claim",
            ),
        ),
        migrations.AddField(
            model_name="openidconnectconfig",
            name="new_username_claim",
            field=mozilla_django_oidc_db.fields.ClaimField(
                base_field=models.CharField(
                    max_length=50, verbose_name="claim path segment"
                ),
                default=mozilla_django_oidc_db.models.get_default_username_claim,
                help_text="The name of the OIDC claim that is used as the username",
                size=None,
                verbose_name="username claim",
            ),
        ),
        migrations.RunPython(copy_forward, copy_reverse),
    ]