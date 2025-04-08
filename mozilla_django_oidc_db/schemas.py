from django.utils.translation import gettext_lazy as _

OPTIONS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Options",
    "description": _("OIDC Configuration options."),
    "type": "object",
    "additionalProperties": True,
    "properties": {
        "user_claim_mappings": {
            "description": _(
                "Mapping between the Django User model fields and a path to a claim value."
            ),
            "type": "object",
            "properties": {
                "username": {
                    "description": _("Path to the claim to use as username."),
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "first_name": {
                    "description": _("Path to the claim to use as first name."),
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "last_name": {
                    "description": _("Path to the claim to use as last name."),
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "email": {
                    "description": _("Path to the claim to use as email."),
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
            },
            "required": ["username"],
            "additionalProperties": True,
        },
        "groups_settings": {
            "description": _(
                "Settings required to assign the created users to the right Django groups."
            ),
            "type": "object",
            "properties": {
                "claim_mapping": {
                    "description": _(
                        "Path to the claim value that contains the groups that the user should be a member of."
                    ),
                    "type": "array",
                    "items": {"type": "string"},
                },
                "sync": {
                    "description": _(
                        "Whether local Django user groups should be created for group names present in the groups claim (if they do not exist)."
                    ),
                    "type": "boolean",
                },
                "sync_pattern": {
                    "description": _(
                        "The glob pattern that local groups must match to be synchronised to the local database."
                    ),
                    "type": "string",
                },
                "default_groups": {
                    "description": _(
                        "Names of the groups to which every user logging in with OIDC will be assigned."
                    ),
                    "type": "array",
                    "items": {"type": "string"},
                },
                "make_users_staff": {
                    "description": _(
                        "Users will be flagged as being a staff user automatically. This allows users to login to the admin interface. By default they have no permissions, even if they are staff."
                    ),
                    "type": "boolean",
                },
                "superuser_group_names": {
                    "description": _(
                        "If any of these group names are present in the claims upon login, the user will be marked as a superuser. If none of these groups are present the user will lose superuser permissions."
                    ),
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
    },
}
