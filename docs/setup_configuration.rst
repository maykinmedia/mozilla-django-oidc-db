==========================
Django Setup Configuration
==========================

There is optional support for`django-setup-configuration`_ that allows you to automatically configure the
OpenID Connect configuration the ``setup_configuration`` commmand.

You must install the ``setupconfig`` dependency group:

.. _django-setup-configuration: https://pypi.org/project/django-setup-configuration/


.. code-block:: bash

    pip install mozilla-django-oidc-db[setupconfig]


You must then define the required and any optional django settings mentioned below and
put the ``AdminOIDCConfigurationStep`` in your django-setup-configuration steps:

.. code-block:: python

    SETUP_CONFIGURATION_STEPS = [
        ...
        "mozilla_django_oidc_db.setup_config.AdminOIDCConfigurationStep",
        ...
    ]

Configuration Settings:
=======================

* ``OIDC_DB_CONFIG_ENABLE``: enable setup configuration step

* ``OIDC_DB_SETUP_CONFIG_ADMIN_AUTH``: Dictionary that maps OIDC fields to their values.


Example:

.. code-block:: python

    OIDC_DB_SETUP_CONFIG_ADMIN_AUTH = {
        "oidc_rp_client_id": "client-id",
        "oidc_rp_client_secret": "secret",
        "oidc_op_discovery_endpoint": "https://keycloak.local/protocol/openid-connect/",
    }


Required Fields:
""""""""""""""""


* ``oidc_rp_client_id``: OpenID Connect client ID from the OIDC Provider.
* ``oidc_rp_client_secret``: OpenID Connect secret from the OIDC Provider.

The discovery endpoint can be configured to automatically fetch the other endpoints. Otherwise the endpoints must be set individually.

* ``oidc_op_discovery_endpoint``: URL of your OpenID Connect provider discovery endpoint ending with a slash (`.well-known/...` will be added automatically).

   **OR**

* ``oidc_op_authorization_endpoint``: URL of your OpenID Connect provider authorization endpoint
* ``oidc_op_token_endpoint``: URL of your OpenID Connect provider token endpoint
* ``oidc_op_user_endpoint``: URL of your OpenID Connect provider userinfo endpoint



Optional Fields:
""""""""""""""""

* ``oidc_op_jwks_endpoint``: URL of your OpenID Connect provider JSON Web Key Set endpoint.
  Required if ``RS256`` is used as signing algorithm. No default value.
* ``claim_mapping``: Mapping from user-model fields to OIDC claims.
  Defaults to ``{"email": ["email"], "first_name": ["given_name"], "last_name": ["family_name"]}``
* ``username_claim``: The name of the OIDC claim that is used as the username. Defaults to ``["sub"]``
* ``groups_claim``: The name of the OIDC claim that holds the values to map to local user groups. Defaults to ``["roles"]``
* ``default_groups``: The default groups to which every user logging in with OIDC will be assigned.  No default values.
* ``superuser_group_names``: If any of these group names are present in the claims upon login, the user will be marked as a superuser.
  If none of these groups are present the user will lose superuser permissions. Defaults to empty list.
* ``make_users_staff``: Users will be flagged as being a staff user automatically.
  This allows users to login to the admin interface. Defaults to ``False``.
* ``oidc_use_nonce``:  Controls whether the OpenID Connect client uses nonce verification. Defaults to ``True``.
* ``oidc_nonce_size``: Sets the length of the random string used for OpenID Connect nonce verification. Defaults to ``32``.
* ``oidc_state_size``: Sets the length of the random string used for OpenID Connect state verification. Defaults to ``32``.
* ``oidc_rp_idp_sign_key``:  Key the Identity Provider uses to sign ID tokens in the case of an RSA sign algorithm.
  Should be the signing key in PEM or DER format. No default.
* ``oidc_rp_scopes_list``: OpenID Connect scopes that are requested during login. Defaults to ``["openid", "email", "profile"]``.
* ``oidc_rp_sign_algo``: Algorithm the Identity Provider uses to sign ID tokens. Defaults to ``"HS256"``.
* ``sync_groups``: If checked, local user groups will be created for group names present in the groups claim,
  if they do not exist yet locally. Defaults to ``True``.
* ``sync_groups_glob_pattern``: The glob pattern that groups must match to be synchronized to the local database. Defaults to ``"*"``.
* ``userinfo_claims_source``: Indicates the source from which the user information claims should be extracted
  (``"userinfo_endpoint"`` or ``"id_token"``). Defaults to ``"userinfo_endpoint"``.
