# Generated by Django 4.2.15 on 2024-10-25 14:15

from django.db import migrations
import django_jsonform.models.fields
import mozilla_django_oidc_db.models


class Migration(migrations.Migration):

    dependencies = [
        ("mozilla_django_oidc_db", "0004_remove_openidconnectconfig_oidc_exempt_urls"),
    ]

    operations = [
        migrations.AlterField(
            model_name="openidconnectconfig",
            name="claim_mapping",
            field=django_jsonform.models.fields.JSONField(
                default=mozilla_django_oidc_db.models.get_claim_mapping,
                help_text="Mapping from user-model fields to OIDC claims",
                verbose_name="claim mapping",
            ),
        ),
    ]