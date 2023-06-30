# Generated by Django 3.2.14 on 2022-08-03 08:08

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0001_initial"),
        ("mozilla_django_oidc_db", "0008_auto_20220422_0849"),
    ]

    operations = [
        migrations.AddField(
            model_name="openidconnectconfig",
            name="default_groups",
            field=models.ManyToManyField(
                blank=True,
                help_text="The default groups to which every user logging in with OIDC will be assigned",
                to="auth.Group",
                verbose_name="default groups",
            ),
        ),
    ]
