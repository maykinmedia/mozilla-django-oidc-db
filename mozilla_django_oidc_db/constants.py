# Mapping the configuration model fieldnames for endpoints to their
# corresponding names in the OIDC spec
OIDC_MAPPING = {
    "oidc_op_authorization_endpoint": "authorization_endpoint",
    "oidc_op_token_endpoint": "token_endpoint",
    "oidc_op_user_endpoint": "userinfo_endpoint",
    "oidc_op_jwks_endpoint": "jwks_uri",
    "oidc_op_logout_endpoint": "end_session_endpoint",
}

OPEN_ID_CONFIG_PATH = ".well-known/openid-configuration"

CONFIG_CLASS_SESSION_KEY = "_OIDCDB_CONFIG_CLASS"

CLAIM_MAPPING_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Claim Mapping",
    "description": "Mapping from user-model fields to OIDC claims",
    "type": "object",
    "properties": {},
    "additionalProperties": {
        "description": "mapping",
        "type": "array",
        "items": {"type": "string"},
    },
}
