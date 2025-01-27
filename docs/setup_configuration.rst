==========================
Django Setup Configuration
==========================

There is optional support for `django-setup-configuration`_ that allows you to automatically configure the
OpenID Connect configuration using that package's ``setup_configuration`` command.

.. autoclass:: mozilla_django_oidc_db.setup_configuration.steps.AdminOIDCConfigurationStep
    :noindex:


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

.. setup-config-example:: mozilla_django_oidc_db.setup_configuration.steps.AdminOIDCConfigurationStep

This file is then used with the setup configuration command setup the OIDC admin:

.. code-block:: Bash

    python manage.py setup_configuration --yaml-file path/to/setup_config.yml
