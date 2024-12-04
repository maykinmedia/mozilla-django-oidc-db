==========================
Django Setup Configuration
==========================

There is optional support for `django-setup-configuration`_ that allows you to automatically configure the
OpenID Connect configuration using that package's ``setup_configuration`` command.

You must install the ``setup-configuration`` dependency group:

.. _django-setup-configuration: https://pypi.org/project/django-setup-configuration/


.. code-block:: bash

    pip install mozilla-django-oidc-db[setup-configuration]


You must then define the required and any optional django settings mentioned below and
put the ``AdminOIDCConfigurationStep`` in your django-setup-configuration steps:

.. code-block:: python

    SETUP_CONFIGURATION_STEPS = [
        ...
        "mozilla_django_oidc_db.setup_configuration.steps.AdminOIDCConfigurationStep",
        ...
    ]

Setup Configuration Settings:
=============================


The setup configuration source must contain the following base keys to use this setup configuration step (using ``yaml`` as an example):

* ``oidc_db_config_enable``: enable setup configuration step boolean

* ``oidc_db_config_admin_auth``: Dictionary that maps OIDC fields to their values.


Example: *setup_config.yml*

.. code-block:: YAML

    other_enable: True
    other_config:
    ...
    oidc_db_config_enable: True
    oidc_db_config_admin_auth:
      oidc_rp_client_id: client-id
      oidc_rp_client_secret: secret
      endpoint_config:
        oidc_op_discovery_endpoint: https://keycloak.local/protocol/openid-connect/
    ...

This is file is then used with the setup configuration command setup the OIDC admin:

.. code-block:: Bash

    python manage.py setup_configuration --yaml-file path/to/setup_config.yml


Any field from the ``OpenIDConnectConfig`` can be added to ``oidc_db_config_admin_auth`` (except endpoints, see below)

Required Fields:
""""""""""""""""


* :model_field:`mozilla_django_oidc_db.models.OpenIDConnectConfig.oidc_rp_client_id`
* :model_field:`mozilla_django_oidc_db.models.OpenIDConnectConfig.oidc_rp_client_secret`
* ``endpoint_config``: Dictionary containing endpoint information

    *  :model_field:`mozilla_django_oidc_db.models.OpenIDConnectConfig.oidc_op_discovery_endpoint`

            **OR**

    * :model_field:`mozilla_django_oidc_db.models.OpenIDConnectConfig.oidc_op_authorization_endpoint`
    * :model_field:`mozilla_django_oidc_db.models.OpenIDConnectConfig.oidc_op_token_endpoint`
    * :model_field:`mozilla_django_oidc_db.models.OpenIDConnectConfig.oidc_op_user_endpoint`

The endpoints must be provided in the ``endpoint_config`` dictionary.
You can add the discovery endpoint to automatically fetch the other endpoints.
Otherwise the endpoints must be specified individually.
Providing both will cause the validation to fail.

Optional Fields:
""""""""""""""""
.. warning::

    Values that are not provided will use the default or empty value and will overwrite any setting changed in the admin.
    Make sure settings that were manually changed in the admin are added to the configuration yaml.

All the following keys are placed in the ``oidc_db_config_admin_auth`` dictionary.

.. model_fields:: mozilla_django_oidc_db.models.OpenIDConnectConfig

    enabled
    oidc_op_jwks_endpoint
    claim_mapping
    username_claim
    groups_claim
    default_groups
    superuser_group_names
    make_users_staff
    oidc_use_nonce
    oidc_nonce_size
    oidc_state_size
    oidc_rp_idp_sign_key
    oidc_rp_scopes_list
    oidc_rp_sign_algo
    sync_groups
    sync_groups_glob_pattern
    userinfo_claims_source
