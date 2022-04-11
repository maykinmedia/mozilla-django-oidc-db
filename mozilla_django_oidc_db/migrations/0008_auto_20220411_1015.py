# Generated by Django 3.2.12 on 2022-04-11 08:15

from django.db import migrations

from mozilla_django_oidc_db.utils import (
    migrate_endpoints_backward,
    migrate_endpoints_forward,
)


def migrate_endpoints(apps, schema_editor):
    OpenIDConnectConfig = apps.get_model(
        "mozilla_django_oidc_db", "OpenIDConnectConfig"
    )
    OpenIDConnectEndpointsConfig = apps.get_model(
        "mozilla_django_oidc_db", "OpenIDConnectEndpointsConfig"
    )

    migrate_endpoints_forward(OpenIDConnectConfig, OpenIDConnectEndpointsConfig)


def migrate_endpoints_reverse(apps, schema_editor):
    OpenIDConnectConfig = apps.get_model(
        "mozilla_django_oidc_db", "OpenIDConnectConfig"
    )
    OpenIDConnectEndpointsConfig = apps.get_model(
        "mozilla_django_oidc_db", "OpenIDConnectEndpointsConfig"
    )

    migrate_endpoints_backward(OpenIDConnectConfig, OpenIDConnectEndpointsConfig)


class Migration(migrations.Migration):

    dependencies = [
        ("mozilla_django_oidc_db", "0007_auto_20220411_1011"),
    ]

    operations = [
        migrations.RunPython(
            migrate_endpoints, reverse_code=migrate_endpoints_reverse
        ),
    ]
