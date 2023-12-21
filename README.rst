

.. mozilla_django_oidc_db documentation master file, created by startproject.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to mozilla_django_oidc_db's documentation!
==================================================

:Version: 0.13.0
:Source: https://github.com/maykinmedia/mozilla-django-oidc-db
:Keywords: OIDC, django, database, authentication
:PythonVersion: 3.7

|build-status| |coverage| |black|

|python-versions| |django-versions| |pypi-version|

Database-backed settings for mozilla-django-oidc, with modified unique identifiers

.. contents::

.. section-numbering::

Features
========

* Thin layer on top of `mozilla-django-oidc`_
* Allows configuration of OpenID Connect variables via django-solo
* Overrides `mozilla-django-oidc`_ default behaviour, using the ``sub`` claim
  instead of the ``email`` claim as unique identifier for users

``mozilla-django-oidc-db`` provides a database singleton for several configuration
variables required for ``mozilla-django-oidc``, moving them from deploy-time to run-time.
This enables modification of the configuration, without having to restart the application.

Additionally, ``mozilla-django-oidc-db`` by default uses the ``sub`` (subject) claim
instead of the ``email`` claim as the unique identifier for users in the RP (Relying Party) application.
Using ``email`` as the unique identifier is not recommended, as mentioned in the `OpenID Connect specification`_.

Installation
============

Requirements
------------

* Python 3.7 or above
* setuptools 30.4.0 or above
* Django 3.2 or newer
* A database supporting ``models.JSONField``


Install
-------

.. code-block:: bash

    pip install mozilla-django-oidc-db

This will also install the following packages:

- ``mozilla-django-oidc``
- ``django-solo``
- ``django-better-admin-arrayfield``

Django settings
---------------

Make sure the following libraries are added to your ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        ...
        "django_better_admin_arrayfield",
        "solo",
        "mozilla_django_oidc",
        "mozilla_django_oidc_db",
        ...
    ]

Add ``mozilla_django_oidc_db.backends.OIDCAuthenticationBackend`` to the ``AUTHENTICATION_BACKENDS``,
this backend replaces ``mozilla_django_oidc.auth.OIDCAuthenticationBackend``:

.. code-block:: python

    AUTHENTICATION_BACKENDS = [
        ...
        "mozilla_django_oidc_db.backends.OIDCAuthenticationBackend",
        ...
    ]

Ensure that ``LOGIN_REDIRECT_URL`` and ``LOGOUT_REDIRECT_URL`` are configured. For example:

.. code-block:: python

    LOGIN_REDIRECT_URL = reverse_lazy("admin:index")
    LOGOUT_REDIRECT_URL = reverse_lazy("admin:index")

To enable validation of ID tokens by renewing them, add ``mozilla_django_oidc_db.middleware.SessionRefresh``
to the middleware, this middleware replaces ``mozilla_django_oidc.middleware.SessionRefresh``:

.. code-block:: python

    MIDDLEWARE = [
        # middleware involving session and authentication must come first
        ...
        "mozilla_django_oidc_db.middleware.SessionRefresh",
        ...
    ]

Furthermore, ensure the following settings are configured:

.. code-block:: python

    OIDC_AUTHENTICATE_CLASS = "mozilla_django_oidc_db.views.OIDCAuthenticationRequestView"
    OIDC_CALLBACK_CLASS = "mozilla_django_oidc_db.views.OIDCCallbackView"
    MOZILLA_DJANGO_OIDC_DB_CACHE = "oidc"
    MOZILLA_DJANGO_OIDC_DB_CACHE_TIMEOUT = 1

In order to properly catch admin login errors, add the following to urlpatterns:

.. code-block:: python

    from mozilla_django_oidc_db.views import AdminLoginFailure

    urlpatterns = [
        ...
        path("admin/login/failure/", AdminLoginFailure.as_view(), name="admin-oidc-error"),
        ...
    ]

``MOZILLA_DJANGO_OIDC_DB_CACHE`` is used to cache the configuration that is stored in the database,
to prevent a lot of database lookups. Ensure this cache is configured in ``CACHES`` (using the backend of choice):

.. code-block:: python

    CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
        ...
        "oidc": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    }

Add the urlpatterns:

.. code-block:: python

    urlpatterns = [
        ...
        path("oidc/", include("mozilla_django_oidc.urls")),
        ...
    ]

Add the login link to your templates:

.. code-block:: django

    {% get_solo 'mozilla_django_oidc_db.OpenIDConnectConfig' as oidc_config %}
    {% if oidc_config.enabled %}
    <div class="submit-row">
        <a href="{% url 'oidc_authentication_init' %}">{% trans "Login with OIDC" %}</a>
    </div>
    {% endif %}

Usage
=====

Now OpenID Connect can be enabled/disabled via the admin (disabled by default)
and the following settings for OpenID Connect can be configured in the admin:

- ``oidc_rp_client_id``
- ``oidc_rp_client_secret``
- ``oidc_rp_sign_algo``
- ``oidc_rp_scopes_list``
- ``oidc_op_discovery_endpoint``
- ``oidc_op_jwks_endpoint``
- ``oidc_op_authorization_endpoint``
- ``oidc_op_token_endpoint``
- ``oidc_op_user_endpoint``
- ``oidc_rp_idp_sign_key``

If the ``oidc_op_discovery_endpoint`` is supplied, the other endpoints will be derived
from this discovery endpoint.

In case no value is provided for one of these variables, the default from ``mozilla-django-oidc``
will be used (if there is one). A detailed description of all settings can be found in the `mozilla-django-oidc settings documentation`_

For more detailed documentation, refer to the `mozilla-django-oidc documentation`_. In this documentation
the origin of the admin configurable settings is also explained.

User profile
------------

In order to set certain attributes on the ``User`` object, a ``claim_mapping``
can be specified via the admin. This maps the names of claims returned by the OIDC provider to
fields on the ``User`` model, and whenever a ``User`` is created/updated, these
fields will be set to the values of these claims.

Assigning users to groups
-------------------------

When users are created/updated, they can be automatically assigned to ``Groups``
by checking the ``Synchronize groups`` option in the admin and setting the
appropriate value for ``Groups claim``, which is the name of the claim that
contains the groups the user is assigned to by the OIDC provider.

Additionally, a ``groups glob pattern`` can be supplied to only sync groups with
specific names (default ``*``, to match all groups).

**NOTE**: The names of the groups in the environment of the OIDC provider must match **exactly**
with the names of the ``Groups`` in Django for this to work.

Custom username claim
---------------------

The name of the claim that is used for the ``User.username`` property
can be configured via the admin. By default, the username is derived from the ``sub`` claim that
is returned by the OIDC provider.

If the desired claim is nested in one or more objects, its path can be specified with dots, e.g.:

.. code-block:: json

    {
        "some": {
            "nested": {
                "claim": "foo"
            }
        }
    }

Can be retrieved by setting the username claim to ``some.nested.claim``

**NOTE**: the username claim does not support claims that have dots in their name, it cannot be configured to retrieve the following claim for instance:

.. code-block:: json

    {
        "some.dotted.claim": "foo"
    }

User information claims source
------------------------------
There are currently two methods to extract information about the authenticated user, controlled by the `User information claims extracted from` option.

- `Userinfo endpoint`, this is the default method (this is also the default behavior in `mozilla-django-oidc`)
- `ID token`, to extract the claims from the ID token. This could be preferable in the case where
  the authentication server passes sensitive claims (that should not be stored in the authentication server itself)
  via the ID token


Claim obfuscation
-----------------

By default, the received claims will be logged when verifying them during the authentication process.
In order to not log information from sensitive claims (identifiers, etc.),
claims can be obfuscated by setting ``OIDCAuthenticationBackend.sensitive_claim_names``
or overriding ``OIDCAuthenticationBackend.get_sensitive_claim_names``.
By default, the configured ``OIDCAuthenticationBackend.config_identifier_field`` will be obfuscated.

Customizing the configuration
-----------------------------

The database-stored configuration class can easily be extended by inheriting from the
``OpenIDConnectConfigBase`` class and then setting the ``OIDCAuthenticationRequestView.config_class``
and ``OIDCAuthenticationBackend.config_class`` to be this new class.

.. |build-status| image:: https://github.com/maykinmedia/mozilla-django-oidc-db/workflows/Run%20CI/badge.svg?branch=master
    :target: https://github.com/maykinmedia/mozilla-django-oidc-db/actions?query=workflow%3A%22Run+CI%22+branch%3Amaster

.. |coverage| image:: https://codecov.io/gh/maykinmedia/mozilla-django-oidc-db/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/maykinmedia/mozilla-django-oidc-db
    :alt: Coverage status

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/mozilla_django_oidc_db.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/mozilla_django_oidc_db.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/mozilla_django_oidc_db.svg
    :target: https://pypi.org/project/mozilla_django_oidc_db/

.. _mozilla-django-oidc: https://github.com/mozilla/mozilla-django-oidc

.. _mozilla-django-oidc settings documentation: https://mozilla-django-oidc.readthedocs.io/en/stable/settings.html

.. _mozilla-django-oidc documentation: https://mozilla-django-oidc.readthedocs.io/en/stable/installation.html

.. _OpenID Connect specification: https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
