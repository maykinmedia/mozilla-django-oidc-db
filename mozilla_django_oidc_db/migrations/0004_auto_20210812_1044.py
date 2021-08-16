# Generated by Django 2.2.24 on 2021-08-12 10:44

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models

import mozilla_django_oidc_db.models


class Migration(migrations.Migration):

    dependencies = [
        ("mozilla_django_oidc_db", "0003_auto_20210719_0803"),
    ]

    operations = [
        migrations.AddField(
            model_name="openidconnectconfig",
            name="claim_mapping",
            field=django.contrib.postgres.fields.jsonb.JSONField(
                default=mozilla_django_oidc_db.models.get_claim_mapping,
                help_text="Mapping from user-model fields to OIDC claims",
                verbose_name="claim mapping",
            ),
        ),
        migrations.AddField(
            model_name="openidconnectconfig",
            name="groups_claim",
            field=models.CharField(
                default="roles",
                help_text="The name of the OIDC claim that holds the values to map to local user groups.",
                max_length=50,
                verbose_name="groups claim",
            ),
        ),
        migrations.AddField(
            model_name="openidconnectconfig",
            name="make_users_staff",
            field=models.BooleanField(
                default=False,
                help_text="Users will be flagged as being a staff user automatically. This allows users to login to the admin interface. By default they have no permissions, even if they are staff.",
                verbose_name="make users staff",
            ),
        ),
        migrations.AddField(
            model_name="openidconnectconfig",
            name="sync_groups",
            field=models.BooleanField(
                default=True,
                help_text="Synchronize the local user groups with the provided groups. Note that this means a user is removed from all groups if there is no group claim. Uncheck to manage groups manually.",
                verbose_name="synchronize groups",
            ),
        ),
    ]