from django.db import migrations

import mozilla_django_oidc_db.fields


class Migration(migrations.Migration):
    dependencies = [
        ("mozilla_django_oidc_db", "0009_delete_openidconnectconfig"),
    ]

    operations = [
        migrations.AlterField(
            model_name="oidcclient",
            name="oidc_rp_client_secret",
            field=mozilla_django_oidc_db.fields.EncryptedCharField(
                help_text="Secret provided by the OIDC Provider",
                verbose_name="Secret",
            ),
        ),
        migrations.AlterField(
            model_name="oidcclient",
            name="oidc_rp_idp_sign_key",
            field=mozilla_django_oidc_db.fields.EncryptedCharField(
                blank=True,
                help_text=(
                    "Key the Identity Provider uses to sign ID tokens in the case of an RSA sign algorithm. "
                    "Should be the signing key in PEM or DER format."
                ),
                verbose_name="Sign key",
            ),
        ),
    ]
