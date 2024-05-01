# Generated by Django 4.2.9 on 2024-05-01 15:32

from django.db import migrations, models

import django_jsonform.models.fields

import mozilla_django_oidc_db.models


class Migration(migrations.Migration):

    replaces = [
        ("mozilla_django_oidc_db", "0001_initial"),
        (
            "mozilla_django_oidc_db",
            "0002_openidconnectconfig_oidc_op_discovery_endpoint",
        ),
        ("mozilla_django_oidc_db", "0003_auto_20210719_0803"),
        ("mozilla_django_oidc_db", "0004_auto_20210812_1044"),
        ("mozilla_django_oidc_db", "0005_openidconnectconfig_sync_groups_glob_pattern"),
        ("mozilla_django_oidc_db", "0006_openidconnectconfig_unique_id_claim"),
        ("mozilla_django_oidc_db", "0007_auto_20220307_1128"),
        ("mozilla_django_oidc_db", "0008_auto_20220422_0849"),
        ("mozilla_django_oidc_db", "0009_openidconnectconfig_default_groups"),
        ("mozilla_django_oidc_db", "0010_openidconnectconfig_userinfo_claims_source"),
        (
            "mozilla_django_oidc_db",
            "0011_alter_openidconnectconfig_userinfo_claims_source",
        ),
        ("mozilla_django_oidc_db", "0012_openidconnectconfig_superuser_group_names"),
        ("mozilla_django_oidc_db", "0012_alter_openidconnectconfig_sync_groups"),
        ("mozilla_django_oidc_db", "0013_merge_20231221_1529"),
        ("mozilla_django_oidc_db", "0014_alter_openidconnectconfig_groups_claim"),
        (
            "mozilla_django_oidc_db",
            "0015_openidconnectconfig_oidc_token_use_basic_auth",
        ),
    ]

    dependencies = [
        ("auth", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="OpenIDConnectConfig",
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
                    "oidc_op_discovery_endpoint",
                    models.URLField(
                        blank=True,
                        help_text="URL of your OpenID Connect provider discovery endpoint ending with a slash (`.well-known/...` will be added automatically). If this is provided, the remaining endpoints can be omitted, as they will be derived from this endpoint.",
                        max_length=1000,
                        verbose_name="Discovery endpoint",
                    ),
                ),
                (
                    "claim_mapping",
                    models.JSONField(
                        default=mozilla_django_oidc_db.models.get_claim_mapping,
                        help_text="Mapping from user-model fields to OIDC claims",
                        verbose_name="claim mapping",
                    ),
                ),
                (
                    "groups_claim",
                    models.CharField(
                        blank=True,
                        default="roles",
                        help_text="The name of the OIDC claim that holds the values to map to local user groups.",
                        max_length=50,
                        verbose_name="groups claim",
                    ),
                ),
                (
                    "make_users_staff",
                    models.BooleanField(
                        default=False,
                        help_text="Users will be flagged as being a staff user automatically. This allows users to login to the admin interface. By default they have no permissions, even if they are staff.",
                        verbose_name="make users staff",
                    ),
                ),
                (
                    "sync_groups",
                    models.BooleanField(
                        default=True,
                        help_text="If checked, local user groups will be created for group names present in the groups claim, if they do not exist yet locally.",
                        verbose_name="Create local user groups if they do not exist yet",
                    ),
                ),
                (
                    "sync_groups_glob_pattern",
                    models.CharField(
                        default="*",
                        help_text="The glob pattern that groups must match to be synchronized to the local database.",
                        max_length=255,
                        verbose_name="groups glob pattern",
                    ),
                ),
                (
                    "username_claim",
                    models.CharField(
                        default="sub",
                        help_text="The name of the OIDC claim that is used as the username",
                        max_length=50,
                        verbose_name="username claim",
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
                    "oidc_use_nonce",
                    models.BooleanField(
                        default=True,
                        help_text="Controls whether the OpenID Connect client uses nonce verification",
                        verbose_name="Use nonce",
                    ),
                ),
                (
                    "default_groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The default groups to which every user logging in with OIDC will be assigned",
                        to="auth.group",
                        verbose_name="default groups",
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
                (
                    "superuser_group_names",
                    django_jsonform.models.fields.ArrayField(
                        base_field=models.CharField(
                            max_length=50, verbose_name="Superuser group name"
                        ),
                        blank=True,
                        default=list,
                        help_text="If any of these group names are present in the claims upon login, the user will be marked as a superuser. If none of these groups are present the user will lose superuser permissions.",
                        size=None,
                        verbose_name="Superuser group names",
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
            ],
            options={
                "verbose_name": "OpenID Connect configuration",
            },
        ),
    ]