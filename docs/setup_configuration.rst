==========================
Django Setup Configuration
==========================

There is optional support for ``django-setup-configuration`` that allows you to automatically configure the
OpenID Connect configuration the the ``setup_configuration`` commmand.

You must install the ``setupconfig`` dependency:


.. code-block:: bash

    pip install mozilla-django-oidc-db[setupconfig]


You must then define the required and any optional django settings mentioned below and
put the ``AdminOIDCConfigurationStep`` in your django-setup-configuration steps:

.. code-block:: python

    SETUP_CONFIGURATION_STEPS = [
        ...
        "mozilla_django_oidc_db.setupconfig.bootstrap.auth.AdminOIDCConfigurationStep",
        ...
    ]

Settings Overview
=================


Enable/Disable configuration:
"""""""""""""""""""""""""""""

::

    ADMIN_OIDC_CONFIG_ENABLE



Required:
"""""""""

::

    ADMIN_OIDC_DEFAULT_GROUPS
    ADMIN_OIDC_OIDC_RP_CLIENT_ID
    ADMIN_OIDC_OIDC_RP_CLIENT_SECRET


All settings:
"""""""""""""

::

    ADMIN_OIDC_CLAIM_MAPPING
    ADMIN_OIDC_DEFAULT_GROUPS
    ADMIN_OIDC_GROUPS_CLAIM
    ADMIN_OIDC_MAKE_USERS_STAFF
    ADMIN_OIDC_OIDC_NONCE_SIZE
    ADMIN_OIDC_OIDC_OP_AUTHORIZATION_ENDPOINT
    ADMIN_OIDC_OIDC_OP_DISCOVERY_ENDPOINT
    ADMIN_OIDC_OIDC_OP_JWKS_ENDPOINT
    ADMIN_OIDC_OIDC_OP_TOKEN_ENDPOINT
    ADMIN_OIDC_OIDC_OP_USER_ENDPOINT
    ADMIN_OIDC_OIDC_RP_CLIENT_ID
    ADMIN_OIDC_OIDC_RP_CLIENT_SECRET
    ADMIN_OIDC_OIDC_RP_IDP_SIGN_KEY
    ADMIN_OIDC_OIDC_RP_SCOPES_LIST
    ADMIN_OIDC_OIDC_RP_SIGN_ALGO
    ADMIN_OIDC_OIDC_STATE_SIZE
    ADMIN_OIDC_OIDC_USE_NONCE
    ADMIN_OIDC_SUPERUSER_GROUP_NAMES
    ADMIN_OIDC_SYNC_GROUPS
    ADMIN_OIDC_SYNC_GROUPS_GLOB_PATTERN
    ADMIN_OIDC_USERINFO_CLAIMS_SOURCE
    ADMIN_OIDC_USERNAME_CLAIM

Detailed Information
====================

::

    Variable            ADMIN_OIDC_CLAIM_MAPPING
    Setting             claim mapping
    Description         Mapping from user-model fields to OIDC claims
    Possible values     Mapping: {'some_key': 'Some value'}
    Default value       {'email': 'email', 'first_name': 'given_name', 'last_name': 'family_name'}
    
    Variable            ADMIN_OIDC_GROUPS_CLAIM
    Setting             groups claim
    Description         The name of the OIDC claim that holds the values to map to local user groups.
    Possible values     string, comma-delimited ('foo,bar,baz')
    Default value       roles
    
    Variable            ADMIN_OIDC_MAKE_USERS_STAFF
    Setting             make users staff
    Description         Users will be flagged as being a staff user automatically. This allows users to login to the admin interface. By default they have no permissions, even if they are staff.
    Possible values     True, False
    Default value       False
  
    Variable            ADMIN_OIDC_OIDC_NONCE_SIZE
    Setting             Nonce size
    Description         Sets the length of the random string used for OpenID Connect nonce verification
    Possible values     string representing a positive integer
    Default value       32
    
    Variable            ADMIN_OIDC_OIDC_OP_AUTHORIZATION_ENDPOINT
    Setting             Authorization endpoint
    Description         URL of your OpenID Connect provider authorization endpoint
    Possible values     string (URL)
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_OP_DISCOVERY_ENDPOINT
    Setting             Discovery endpoint
    Description         URL of your OpenID Connect provider discovery endpoint ending with a slash (`.well-known/...` will be added automatically). If this is provided, the remaining endpoints can be omitted, as they will be derived from this endpoint.
    Possible values     string (URL)
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_OP_JWKS_ENDPOINT
    Setting             JSON Web Key Set endpoint
    Description         URL of your OpenID Connect provider JSON Web Key Set endpoint. Required if `RS256` is used as signing algorithm.
    Possible values     string (URL)
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_OP_TOKEN_ENDPOINT
    Setting             Token endpoint
    Description         URL of your OpenID Connect provider token endpoint
    Possible values     string (URL)
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_OP_USER_ENDPOINT
    Setting             User endpoint
    Description         URL of your OpenID Connect provider userinfo endpoint
    Possible values     string (URL)
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_RP_CLIENT_ID
    Setting             OpenID Connect client ID
    Description         OpenID Connect client ID provided by the OIDC Provider
    Possible values     string
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_RP_CLIENT_SECRET
    Setting             OpenID Connect secret
    Description         OpenID Connect secret provided by the OIDC Provider
    Possible values     string
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_RP_IDP_SIGN_KEY
    Setting             Sign key
    Description         Key the Identity Provider uses to sign ID tokens in the case of an RSA sign algorithm. Should be the signing key in PEM or DER format.
    Possible values     string
    Default value       No default
    
    Variable            ADMIN_OIDC_OIDC_RP_SCOPES_LIST
    Setting             OpenID Connect scopes
    Description         OpenID Connect scopes that are requested during login
    Possible values     string, comma-delimited ('foo,bar,baz')
    Default value       openid, email, profile
    
    Variable            ADMIN_OIDC_OIDC_RP_SIGN_ALGO
    Setting             OpenID sign algorithm
    Description         Algorithm the Identity Provider uses to sign ID tokens
    Possible values     string
    Default value       HS256
    
    Variable            ADMIN_OIDC_OIDC_STATE_SIZE
    Setting             State size
    Description         Sets the length of the random string used for OpenID Connect state verification
    Possible values     string representing a positive integer
    Default value       32
    
    Variable            ADMIN_OIDC_OIDC_USE_NONCE
    Setting             Use nonce
    Description         Controls whether the OpenID Connect client uses nonce verification
    Possible values     True, False
    Default value       True
    
    Variable            ADMIN_OIDC_SUPERUSER_GROUP_NAMES
    Setting             Superuser group names
    Description         If any of these group names are present in the claims upon login, the user will be marked as a superuser. If none of these groups are present the user will lose superuser permissions.
    Possible values     string, comma-delimited ('foo,bar,baz')
    Default value       
    
    Variable            ADMIN_OIDC_SYNC_GROUPS
    Setting             Create local user groups if they do not exist yet
    Description         If checked, local user groups will be created for group names present in the groups claim, if they do not exist yet locally.
    Possible values     True, False
    Default value       True
    
    Variable            ADMIN_OIDC_SYNC_GROUPS_GLOB_PATTERN
    Setting             groups glob pattern
    Description         The glob pattern that groups must match to be synchronized to the local database.
    Possible values     string
    Default value       *
    
    Variable            ADMIN_OIDC_USERINFO_CLAIMS_SOURCE
    Setting             user information claims extracted from
    Description         Indicates the source from which the user information claims should be extracted.
    Possible values     userinfo_endpoint, id_token
    Default value       userinfo_endpoint
    
    Variable            ADMIN_OIDC_USERNAME_CLAIM
    Setting             username claim
    Description         The name of the OIDC claim that is used as the username
    Possible values     string, comma-delimited ('foo,bar,baz')
    Default value       sub