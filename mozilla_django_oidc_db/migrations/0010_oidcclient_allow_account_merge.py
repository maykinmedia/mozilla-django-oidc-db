from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("mozilla_django_oidc_db", "0009_delete_openidconnectconfig"),
    ]

    operations = [
        migrations.AddField(
            model_name="oidcclient",
            name="allow_account_merge",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, a first-time OIDC login whose username does not match any "
                    "existing account but whose email address does will trigger a one-time "
                    "account-merge flow. The user must confirm ownership of the existing "
                    "account by providing their current password before the accounts are merged. "
                    "After merging the existing username is replaced with the OIDC identifier "
                    "and the local password is cleared."
                ),
                verbose_name="allow account merge",
            ),
        ),
    ]
