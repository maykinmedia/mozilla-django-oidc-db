import os

from django.urls import reverse_lazy

DEBUG = True

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = "so-secret-i-cant-believe-you-are-looking-at-this"

USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("PGDATABASE", "mozilla_django_oidc_db"),
        "USER": os.getenv("PGUSER", "mozilla_django_oidc_db"),
        "PASSWORD": os.getenv("PGPASSWORD", "mozilla_django_oidc_db"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", 5432),
    }
}

CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    "oidc": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
}

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    "solo",
    "django_jsonform",
    "mozilla_django_oidc",
    "mozilla_django_oidc_db",
    "testapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

ROOT_URLCONF = "testapp.urls"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "mozilla_django_oidc_db.backends.OIDCAuthenticationBackend",
]

# These settings are evaluated at import-time of the urlconf in mozilla_django_oidc.urls.
# Changing them via @override_settings (or the pytest-django settings fixture) has no
# effect.
OIDC_AUTHENTICATE_CLASS = "mozilla_django_oidc_db.views.OIDCAuthenticationRequestView"
OIDC_CALLBACK_CLASS = "mozilla_django_oidc_db.views.OIDCCallbackView"
LOGIN_REDIRECT_URL = reverse_lazy("admin:index")

STATIC_URL = "/static/"


# Setup Configuration Settings

IDENTITY_PROVIDER = "https://keycloak.local/realms/digid/"

ADMIN_OIDC_OIDC_RP_CLIENT_ID = "client-id"
ADMIN_OIDC_OIDC_RP_CLIENT_SECRET = "secret"
ADMIN_OIDC_OIDC_RP_SCOPES_LIST = ["open_id", "email", "profile", "extra_scope"]
ADMIN_OIDC_OIDC_RP_SIGN_ALGO = "RS256"
ADMIN_OIDC_OIDC_RP_IDP_SIGN_KEY = "key"
ADMIN_OIDC_OIDC_OP_DISCOVERY_ENDPOINT = None
ADMIN_OIDC_OIDC_OP_JWKS_ENDPOINT = f"{IDENTITY_PROVIDER}protocol/openid-connect/certs"
ADMIN_OIDC_OIDC_OP_AUTHORIZATION_ENDPOINT = (
    f"{IDENTITY_PROVIDER}protocol/openid-connect/auth"
)
ADMIN_OIDC_OIDC_OP_TOKEN_ENDPOINT = f"{IDENTITY_PROVIDER}protocol/openid-connect/token"
ADMIN_OIDC_OIDC_OP_USER_ENDPOINT = (
    f"{IDENTITY_PROVIDER}protocol/openid-connect/userinfo"
)
ADMIN_OIDC_USERNAME_CLAIM = ["claim_name"]
ADMIN_OIDC_GROUPS_CLAIM = ["groups_claim_name"]
ADMIN_OIDC_CLAIM_MAPPING = {"first_name": "given_name"}
ADMIN_OIDC_SYNC_GROUPS = False
ADMIN_OIDC_SYNC_GROUPS_GLOB_PATTERN = "local.groups.*"
ADMIN_OIDC_DEFAULT_GROUPS = ["Admins", "Read-only"]
ADMIN_OIDC_MAKE_USERS_STAFF = True
ADMIN_OIDC_SUPERUSER_GROUP_NAMES = ["superuser"]
ADMIN_OIDC_OIDC_USE_NONCE = False
ADMIN_OIDC_OIDC_NONCE_SIZE = 48
ADMIN_OIDC_OIDC_STATE_SIZE = 48
ADMIN_OIDC_USERINFO_CLAIMS_SOURCE = "id_token"
