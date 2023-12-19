# Generated by Django 3.2.18 on 2023-12-19 14:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "mozilla_django_oidc_db",
            "0011_alter_openidconnectconfig_userinfo_claims_source",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="openidconnectconfig",
            name="group_mapping",
            field=models.JSONField(
                default=list,
                help_text="Mapping from group names to local groups in the application",
                verbose_name="group mapping",
            ),
        ),
    ]
