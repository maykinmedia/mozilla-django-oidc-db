from collections.abc import Mapping

from .typing import EndpointFieldNames

# Mapping the configuration model fieldnames for endpoints to their
# corresponding names in the OIDC spec
OIDC_MAPPING: Mapping[EndpointFieldNames, str] = {
    "oidc_op_authorization_endpoint": "authorization_endpoint",
    "oidc_op_token_endpoint": "token_endpoint",
    "oidc_op_user_endpoint": "userinfo_endpoint",
    "oidc_op_jwks_endpoint": "jwks_uri",
    "oidc_op_logout_endpoint": "end_session_endpoint",
}

OPEN_ID_CONFIG_PATH = ".well-known/openid-configuration"

CONFIG_IDENTIFIER_SESSION_KEY = "_OIDCDB_CONFIG_IDENTIFIER"

OIDC_ADMIN_CONFIG_IDENTIFIER = "admin-oidc"
OIDC_ADMIN_PROVIDER_CONFIG_IDENTIFIER = "admin-oidc-provider"

UNIQUE_PLUGIN_ID_MAX_LENGTH = 255
