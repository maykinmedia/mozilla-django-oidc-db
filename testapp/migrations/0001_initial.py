# Generated by Django 5.0.4 on 2024-05-24 07:03

from django.db import migrations, models

import django_jsonform.models.fields

import mozilla_django_oidc_db.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("mozilla_django_oidc_db", "0002_migrate_to_claim_field"),
    ]

    operations = [
        migrations.CreateModel(
            name="EmptyConfig",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "enabled",
                    models.BooleanField(
                        default=False,
                        help_text="Indicates whether OpenID Connect for authentication/authorization is enabled",
                        verbose_name="enable",
                    ),
                ),
                (
                    "oidc_rp_client_id",
                    models.CharField(
                        help_text="OpenID Connect client ID provided by the OIDC Provider",
                        max_length=1000,
                        verbose_name="OpenID Connect client ID",
                    ),
                ),
                (
                    "oidc_rp_client_secret",
                    models.CharField(
                        help_text="OpenID Connect secret provided by the OIDC Provider",
                        max_length=1000,
                        verbose_name="OpenID Connect secret",
                    ),
                ),
                (
                    "oidc_rp_sign_algo",
                    models.CharField(
                        default="HS256",
                        help_text="Algorithm the Identity Provider uses to sign ID tokens",
                        max_length=50,
                        verbose_name="OpenID sign algorithm",
                    ),
                ),
                (
                    "oidc_rp_scopes_list",
                    django_jsonform.models.fields.ArrayField(
                        base_field=models.CharField(
                            max_length=50, verbose_name="OpenID Connect scope"
                        ),
                        blank=True,
                        default=mozilla_django_oidc_db.models.get_default_scopes,
                        help_text="OpenID Connect scopes that are requested during login",
                        size=None,
                        verbose_name="OpenID Connect scopes",
                    ),
                ),
                (
                    "oidc_op_discovery_endpoint",
                    models.URLField(
                        blank=True,
                        help_text="URL of your OpenID Connect provider discovery endpoint ending with a slash (`.well-known/...` will be added automatically). If this is provided, the remaining endpoints can be omitted, as they will be derived from this endpoint.",
                        max_length=1000,
                        verbose_name="Discovery endpoint",
                    ),
                ),
                (
                    "oidc_op_jwks_endpoint",
                    models.URLField(
                        blank=True,
                        help_text="URL of your OpenID Connect provider JSON Web Key Set endpoint. Required if `RS256` is used as signing algorithm.",
                        max_length=1000,
                        verbose_name="JSON Web Key Set endpoint",
                    ),
                ),
                (
                    "oidc_op_authorization_endpoint",
                    models.URLField(
                        help_text="URL of your OpenID Connect provider authorization endpoint",
                        max_length=1000,
                        verbose_name="Authorization endpoint",
                    ),
                ),
                (
                    "oidc_op_token_endpoint",
                    models.URLField(
                        help_text="URL of your OpenID Connect provider token endpoint",
                        max_length=1000,
                        verbose_name="Token endpoint",
                    ),
                ),
                (
                    "oidc_token_use_basic_auth",
                    models.BooleanField(
                        default=False,
                        help_text="If enabled, the client ID and secret are sent in the HTTP Basic auth header when obtaining the access token. Otherwise, they are sent in the request body.",
                        verbose_name="Use Basic auth for token endpoint",
                    ),
                ),
                (
                    "oidc_op_user_endpoint",
                    models.URLField(
                        help_text="URL of your OpenID Connect provider userinfo endpoint",
                        max_length=1000,
                        verbose_name="User endpoint",
                    ),
                ),
                (
                    "oidc_rp_idp_sign_key",
                    models.CharField(
                        blank=True,
                        help_text="Key the Identity Provider uses to sign ID tokens in the case of an RSA sign algorithm. Should be the signing key in PEM or DER format.",
                        max_length=1000,
                        verbose_name="Sign key",
                    ),
                ),
                (
                    "oidc_use_nonce",
                    models.BooleanField(
                        default=True,
                        help_text="Controls whether the OpenID Connect client uses nonce verification",
                        verbose_name="Use nonce",
                    ),
                ),
                (
                    "oidc_nonce_size",
                    models.PositiveIntegerField(
                        default=32,
                        help_text="Sets the length of the random string used for OpenID Connect nonce verification",
                        verbose_name="Nonce size",
                    ),
                ),
                (
                    "oidc_state_size",
                    models.PositiveIntegerField(
                        default=32,
                        help_text="Sets the length of the random string used for OpenID Connect state verification",
                        verbose_name="State size",
                    ),
                ),
                (
                    "oidc_exempt_urls",
                    django_jsonform.models.fields.ArrayField(
                        base_field=models.CharField(
                            max_length=1000, verbose_name="Exempt URL"
                        ),
                        blank=True,
                        default=list,
                        help_text="This is a list of absolute url paths, regular expressions for url paths, or Django view names. This plus the mozilla-django-oidc urls are exempted from the session renewal by the SessionRefresh middleware.",
                        size=None,
                        verbose_name="URLs exempt from session renewal",
                    ),
                ),
                (
                    "userinfo_claims_source",
                    models.CharField(
                        choices=[
                            ("userinfo_endpoint", "Userinfo endpoint"),
                            ("id_token", "ID token"),
                        ],
                        default="userinfo_endpoint",
                        help_text="Indicates the source from which the user information claims should be extracted.",
                        max_length=100,
                        verbose_name="user information claims extracted from",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="WrongConfigModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="CustomCallbackViewConfig",
            fields=[],
            options={
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("mozilla_django_oidc_db.openidconnectconfig",),
        ),
    ]
