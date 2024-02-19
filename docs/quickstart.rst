==========
Quickstart
==========

Installation
============

Requirements
------------

* See the badges for the supported Python and Django versions
* A PostgreSQL database (we use ``django.contrib.postgres.fields.ArrayField``)

Install
-------

.. code-block:: bash

    pip install mozilla-django-oidc-db

This will also install the following packages:

- ``mozilla-django-oidc``
- ``django-solo``
- ``django-jsonform``

Django settings
---------------

Make sure the following libraries are added to your ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        ...
        "django_jsonform",
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
and the following settings from ``mozilla-django-oidc`` for OpenID Connect can be configured in the admin:

- ``OIDC_RP_CLIENT_ID``
- ``OIDC_RP_CLIENT_SECRET``
- ``OIDC_RP_SIGN_ALGO``
- ``OIDC_RP_SCOPES`` (via ``oidc_rp_scopes_list``)
- ``OIDC_OP_JWKS_ENDPOINT``
- ``OIDC_OP_AUTHORIZATION_ENDPOINT``
- ``OIDC_OP_TOKEN_ENDPOINT``
- ``OIDC_OP_USER_ENDPOINT``
- ``OIDC_TOKEN_USE_BASIC_AUTH``
- ``OIDC_RP_IDP_SIGN_KEY``
- ``OIDC_USE_NONCE``
- ``OIDC_STATE_SIZE``
- ``OIDC_EXEMPT_URLS``

In case no value is provided for one of these variables, the default from ``mozilla-django-oidc``
will be used (if there is one). A detailed description of all settings can be found in the `mozilla-django-oidc settings documentation`_.

OIDC discovery endpoint
-----------------------

Instead of setting each OIDC endpoint as shown above manually, these endpoints can be
derived by setting the **Discovery endpoint** (ending with a slash).
The path ``.well-known/openid-configuration`` will be added to this URL automatically.

For more information about the discovery endpoint, refer to the the `OIDC spec`_.

Custom username claim
---------------------

The name of the claim that is used for the ``User.username`` property
can be configured via the admin (**Username claim**). By default, the username is derived from the ``sub`` claim that
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

.. note::
    The username claim does not support claims that have dots in their name, it cannot be configured to retrieve the following claim for instance:

.. code-block:: json

    {
        "some.dotted.claim": "foo"
    }

User profile
------------

In order to set other attributes on the ``User`` object, a **Claim mapping**
can be specified via the admin. This maps the names of claims returned by the OIDC provider to
fields on the ``User`` model, and whenever a ``User`` is created/updated, these
fields will be set to the values of these claims.

User information claims source
------------------------------

There are currently two methods to extract information about the authenticated user, controlled by the **User information claims extracted from** (``userinfo_claims_source``) option.

- `Userinfo endpoint`, this is the default method (this is also the default behavior in `mozilla-django-oidc`)
- `ID token`, to extract the claims from the ID token. This could be preferable in the case where
  the authentication server passes sensitive claims (that should not be stored in the authentication server itself)
  via the ID token

Assigning users to groups
-------------------------

When users are created/updated, they can be automatically assigned to ``Groups``
by setting the appropriate value for **Groups claim**, which is the name of the claim that
contains the groups the user is assigned to by the OIDC provider. If **Synchronize groups** is
enabled, local Django user groups will be created for group names present in the groups claim, if they do not exist yet locally.

Additionally, a **Groups glob pattern** can be supplied to only sync groups with
specific names (default ``*``, to match all groups).

.. note::
    The names of the groups in the environment of the OIDC provider must match *exactly*
    with the names of the ``Groups`` in Django for this to work.

In order to assign specific Django groups to *every* OIDC authenticated user, the **Default groups** option can be used.

User permissions
----------------

If the **Make users staff** is enabled, *every* OIDC authenticated user will automatically be made a staff user,
allowing them to login to the admin interface.

In order to promote OIDC authenticated users to superusers, the **Superuser group names** option can be used. This
takes a list of group names and will set ``is_superuser`` to ``True`` if an authenticated user
has at least one of these groups in their **Groups claim**. If a user does not have any of these
groups in their **Groups claim**, ``is_superuser`` will be set to ``False`` for that user.

.. note::
    If **Superuser group names** is left empty, the superuser status of users will never be altered upon login,
    allowing for manual management of superusers.

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

.. _mozilla-django-oidc settings documentation: https://mozilla-django-oidc.readthedocs.io/en/stable/settings.html

.. _OIDC spec: https://openid.net/specs/openid-connect-discovery-1_0.html#WellKnownRegistry