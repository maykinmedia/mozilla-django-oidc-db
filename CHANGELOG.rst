=========
Changelog
=========

1.1.0 (2025-11-18)
==================

Minor release

* [#157] Relocate shared test utility ``keycloak_login`` to ``mozilla_django_oidc_db/tests/utils``
  to make sure upstream projects can make use of it

1.0.2 (2025-10-24)
==================

Bugfix release - same patch as 1.0.1 but fixed some missed cases.

1.0.1 (2025-10-24)
==================

Bugfix release.

* Relaxed the user model inheritance check in the backend.

1.0.0 (2025-10-23)
==================

After a long time we feel the library is finally ready for a 1.0 version!

Releases 0.17.0 and 0.24.0 included a large rework of the architecture of the library,
which we considered essential before even thinking of a 1.0 version. Since then, we've
found no major issues and have adapted the library in a number of real projects in
production with varying degrees of complexity.

From now on, breaking changes will result in a major version bump.

This release itself contains some (technically) breaking changes, but we expect they won't
really affect you.

**💥 Breaking changes**

* Dropped support for Python 3.10
* Dropped support for Python 3.11
* Reworked types and classes used for the plugin system, in particular:

  * Removed :class:`mozilla_django_oidc_db.plugins.OIDCBasePluginProtocol`, instead there is
    an abstract base class :class:`mozilla_django_oidc_db.plugins.BaseOIDCPlugin`.
  * Removed :class:`mozilla_django_oidc_db.plugins.BaseOIDCPlugin`, instead there is
    :class:`mozilla_django_oidc_db.plugins.BaseOIDCPlugin`.
  * Removed :class:`mozilla_django_oidc_db.plugins.AnonymousUserOIDCPluginProtocol`,
    instead there is an abstract base class
    :class:`mozilla_django_oidc_db.plugins.AnonymousUserOIDCPlugin`.
  * Removed :class:`mozilla_django_oidc_db.plugins.AbstractUserOIDCPluginProtocol`,
    instead there is an abstract base class
    :class:`mozilla_django_oidc_db.plugins.AbstractUserOIDCPlugin`.

  Typically now you should only be subclassing either ``AnonymousUserOIDCPlugin`` or
  ``AbstractUserOIDCPlugin`` - they inherit from the abstract base class and provide
  all necessary functionalities.

* The django-setup-configuration format appears to not be (fully) backwards compatible
  since release 0.24.0. Downstream projects should mention this in their changelogs
  and/or provide a migration path.

**New features**

* [`#121`_] Added Dutch translations.

**Bugfixes**

* [`#120`_] Fixed the retrieval of optional endpoints causing database errors.
* [`#113`_] Removed Open Forms reference in generic failure template.

**Project maintenance**

* [`#154`_] Improved documentation for setup-configuration integration.
* Improved the static type hints and added type-checking to the CI pipeline.
* Updated to modern Python syntax.

.. _#154: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/154
.. _#120: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/120
.. _#113: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/113
.. _#121: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/121

0.25.1 (2025-08-25)
===================

Minor changes:

* Add testing utility ``OIDCMixin`` that clear test records and stabilizes state and nonce for VCR (see :ref:`test-mixins-reference`)

0.25.0 (2025-08-08)
===================

Minor changes:

* Added the template tag `get_oidc_admin_client` to retrieve the admin `OIDCClient` in templates.
* Add Ruff for development and CI, format code and exclude linting changes from git blame.
* Fix broken post migrate hook.
* Updated the documentation to reflect the new state of the project after the big refactor.

0.24.0 (2025-08-01)
===================

💥 Major rework release with breaking changes!

The OpenID Connect configuration is no longer a singleton/solo model. Instead, we now
use multiple records in the same database table for different configurations. If you
only use this library for the admin OIDC login, the migration is automatic and the
impact of the changes is minimal.

If you defined your own configuration models/classes based on the abstract base models,
then you the changes do affect you. You can take a look at our data migrations or the
changes in django-digid-eherkenning for some inspiration on how to deal with them.

**Changes**

* Removed django-solo dependency
* Split the solo model configuration into ``OIDCProvider`` configuration and
  ``OIDCClient`` configuration, making it easier to re-use identity provider configuration
  for multiple client IDs.
* Client-specific configuration is now stored in a ``JSONField``, the shape of which is
  determined by JsonSchema definitions via ``django-jsonform``. Each client is expected
  to have a unique identifier.
* Added plugin mechanism to register the schema definition for your own custom client
  identifiers and configuration options.
* Added automatic migration for the admin OIDC login configuration.
* Confirmed support for Python 3.13 and Django 5.2

0.23.0 (2025-04-08)
===================

Feature release to make the ``SessionRefresh`` middleware dynamic config aware.

* The ``SessionRefresh`` middleware would previously hardcode the assumption that, if an
  ID token had expired, the user should be redirected to the IdP as configured by the
  ``OpenIDConnectConfig`` singleton. This would frequently cause issues if multiple OIDC
  backends were configured in parallel, causing a user to be redirected with state and
  session parameters for this singleton, rather than the specific OIDC backend that the
  user used to authenticate. This release uses the session parameters to select the
  correct config model for the active OIDC backend.

**💥 Breaking changes**

The ``mozilla_django_oidc_db.middleware`` module no longer exports
``BaseRefreshMiddleware``. If you previously relied on this class in order to specify a
config class other than the default ``OpenIDConnectConfig``, you should now be able to
just use ``mozilla_django_oidc_db.middleware.SessionRefresh`` and rely on the middleware to select
the appropriate config class.

0.22.0 (2025-01-27)
===================

Small feature release that updates ``setup-configuration`` documentation

* Use generated yaml directive for setup-config docs

0.21.1 (2024-12-10)
===================

A bugfix for the django-setup-configuration YAML format:
* Move ``oidc_op_jwks_endpoint`` and ``oidc_op_logout_endpoint`` to the ``endpoint_config`` key

0.21.0 (2024-12-09)
===================

Some changes to prepare the django-setup-configuration YAML format for when support
for multiple configurations is added:
* Add ``identifier`` field to YAML data to setup configuration
* Modify format of YAML data to accept list of configurations

0.20.0 (2024-12-03)
===================

New Features:

* Add optional support for `django-setup-configuration`_

.. _django-setup-configuration: https://pypi.org/project/django-setup-configuration/

0.19.0 (2024-07-02)
===================

Bugfix and cleanup release

* Fixed broken ``SessionRefresh`` middleware
* Removed ``oidc_exempt_urls`` config model fields - these turn out not to be used and
  you typically want to specify them in django settings as they are tied to the session
  refresh middleware.

0.18.1 (2024-06-18)
===================

Bugfix release

* Redirect responses from the OP_LOGOUT request are no longer followed automatically.

0.18.0 (2024-06-12)
===================

Small feature release

* Added ``mozilla_django_oidc_db.fields.ClaimFieldDefault`` to specify default values
  for ``ClaimField`` in a less verbose way.

0.17.0 (2024-05-28)
===================

This release is a big rewrite and refactor of the library internals.

💥 There are a number of breaking changes, please review the notes further down.

**Why the rework?**

mozilla-django-oidc-db originated in being able to change OpenID Provider configuration
(such as the endpoints, client ID...) on the fly rather than at deploy time. So, we
implemented looking up the settings from a database model rather than the Django
settings, and this worked for a while. The scope was limited to logging in to the admin
interface with OpenID Connect.

Then, authentication flows also relying on OpenID Connect for different types of users
became relevant - one or more different configurations, with different client IDs etc.
This was further complicated that not every configuration should result in a Django user
record being created/updated.

Implementing this in projects was possible, but it involved custom authentication
backends, custom authentication request views and custom callback views to achieve the
desired behaviour, resulting in quite a lot of spread-out code, duplication and
annoyances for the administrators on the OpenID Provider side (adding yet another
new Redirect URI for every configuration flavour...).

The rework addresses all this - customization and extension is still possible through
(custom or proxy) models, but our authentication request view now makes sure to store
which configuration to use in the callback view and authentication backend(s).
Customizing behaviour on the authentication backend level is now also much more in line
with standard Django practices, by using ``settings.AUTHENTICATION_BACKENDS``.

This is a big internal rewrite and mostly affects people that were doing these sort of
customizations. We've incorporated our experiences from the Open Forms and Open Inwoner
projects in this rework and applied "lessons learned".

**💥 Breaking changes**

While we were able to perform most of the changes without breaking public API, some
aspects could not be avoided. The majority are related to customization - for more
details, please read the customization documentation.

* Dropped support for Django 3.2 (and thus also mozilla-django-oidc 3.x). These are no
  longer maintained.

* The attributes ``OIDCAuthenticationBackend.sensitive_claim_names`` and
  ``OIDCAuthenticationBackend.config_identifier_field`` are removed. This affects you
  if you were subclassing this backend to override these attributes.

  You can provide these in your custom configuration model(s) as the
  ``oidcdb_sensitive_claims`` and ``oidcdb_username_claim`` model fields or properties.
  See the implementation of the ``OpenIDConnectConfigBase`` model for more details.

* The ``GetAttributeMixin``, ``SoloConfigMixin`` and generic type support for
  ``OIDCAuthenticationBackend`` are removed. Instead of the dynamic attribute lookups,
  you can use ``mozilla_django_oidc_db.config.dynamic_setting``. The solo config mixin
  is no longer relevant, because the ``config_class`` attribute is set during
  the ``authenticate`` method call, and that also removed the necessity for generic
  types.

* Custom callback views should generally not be necessary anymore to modify user
  authentication/creation/updating behaviour. Instead, you should probably use a custom
  authentication backend and add that to your Django settings. However, if you modify
  the authentication views to add error handling or different redirect behaviour on
  success/error, you should subclass
  ``mozilla_django_oidc_db.views.OIDCAuthenticationCallbackView`` rather than
  ``OIDCCallbackView`` (the latter now acts as a router). You can point from the config
  model to the view to use for this.

* The ``GetAttributeMixin`` and ``SoloConfigMixin`` for ``SessionRefresh`` are removed,
  instead you can use the ``dynamic_setting`` descriptor (similar to the authentication
  backend change).

* The django-solo caching mixin is removed from the models. The configuration is only
  retrieved when authenticating, and the regular django-solo cache settings apply. We
  do however modify the cache key so that it points to a unique django model to look up.

* The fields ``oidc_kc_idp_hint`` and ``oidc_op_logout_endpoint`` are added to the base
  model. If you specify these yourself, remove them from your own models. You'll need to
  run ``makemigrations`` to update your own models.

**New features**

* [#99] Improved support for customizing authentication behaviour. See the new section
  in the documentation for details.
* [#102] Added system checks.
* [#42] Added keycloak IDP hint configuration field and logout endpoint.

**Project maintenance**

* Added more (technical) documentation - both user-guide style and API reference docs.
* Improved quality of tests - we avoid mocks and favour testing against real OpenID
  Providers (using VCR.py).

0.16.0 (2024-05-02)
===================

* [`#84`_] Updated usage section in README
* [`#88`_] Set up Sphinx documentation on readthedocs
* [`#94`_] Claims with "." characters in them are now supported
* [`#92`_] Fixed a crash when validating the user claim mapping

.. _#84: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/84
.. _#88: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/88
.. _#94: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/94
.. _#92: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/92

0.15.0 (2024-02-07)
===================

**Breaking changes**

* Dropped support for Django 4.1
* Dropped support for Python 3.8 and 3.9
* Dropped support for mozilla-django-oidc 2.0

**New features**

* Confirmed support for mozilla-django-oidc 4.0
* Confirmed support for Python 3.12
* [`#80`_] Added configuration to call token endpoint with HTTP Basic Auth
* [`#83`_] Support ``application/jwt`` responses from userinfo endpoint

**Project maintenance/refactors**

* Added more typehints
* Added docker-compose setup for Keycloak OIDC Provider
* Added VCR for testing against real OIDC provider(s)

.. _#80: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/80
.. _#83: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/83

0.14.1 (2024-01-12)
===================

* [`#76`_] Make groups_claim optional (to allow disabling of group assignment)

.. _#76: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/76

0.14.0 (2024-01-05)
===================

Django 4.2+ compatibility update

* Replaced django-better-admin-arrayfield with django-jsonform, the former does not work
  on modern Django versions.

0.13.0 (2023-12-21)
===================

* [`#65`_] Add functionality to make users superuser based on groups
* [`#68`_] More clear label/helptext for sync_groups

.. _#65: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/65
.. _#68: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/68

0.12.0 (2022-12-14)
===================

* [`#59`_]  Config option to get user info from ID token

.. _#59: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/59


0.11.0 (2022-08-09)
===================

* [`#56`_] Add default_groups option to OIDC config
* Catch validation errors during auth process and display the message on error page

.. _#56: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/56


0.10.1 (2022-07-27)
===================

**Bugfixes**

* [`#51`_] Use defaults from SessionRefresh if variable not provided

**Project maintenance/refactors**

* [`#48`_] Document claim obfuscation in README


.. _#51: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/51
.. _#48: https://github.com/maykinmedia/mozilla-django-oidc-db/issues/48


0.10.0 (2022-04-25)
===================

**Breaking changes**

* Dropped support for Django < 3.2
* Dropped support for Python 3.6

**New features**

* Migrated from ``django.contrib.postgres.fields.JSONField`` to ``models.JSONField``, so
  you can use databases other than PostgreSQL.
* Added support for Django 4.0

**Project maintenance/refactors**

* Cleaned up test suite and solved deprecation warnings/runtime warnings
* Updated support python/django versions in CI configuration

0.9.0 (2022-04-21)
==================

**New features**

* Added support for mozilla-django-oidc 2.x (#16)
* Added ability to obfuscate claim values for logging output (#42)
* Added ability to specify (nested) identifier claim to extract (#42)
* Customizable SoloModel cache prefix via CachingMixin
* Add views to properly handle admin login failure (#33)

**Project maintenance/refactors**

* Define generic base class for OIDC config fields
* Removed unused Travis CI config
* Explicitly return None for empty values from config
* Added typehints

0.8.0 (2022-02-15)
==================

* Allow usage of other config classes in SoloConfigMixin

0.7.2 (2022-01-11)
==================

* Fix caching issues caused by `OpenIDConnectConfig.get_solo` in backend initialization (#30)
* Rename imported `SessionRefresh` in middleware to avoid conflicting names

0.7.1 (2021-11-29)
==================

* Fix verbose_name/help_text in username_claim migration

0.7.0 (2021-11-29) **YANKED**
=============================

* Add configurable username claim (defaults to ``sub``)

0.6.0 (2021-11-26)
==================

* Add configurable glob pattern for groups sync, to only sync groups that match the pattern
* Fix OIDC config form for users with readonly access

0.5.0 (2021-09-13)
==================

* Pin mozilla-django-oidc to >=1.0.0, <2.0.0 (due to compatibility issues)
* Adapt admin form to allow configurable endpoints that must be derived from discovery endpoint

0.4.0 (2021-08-16)
==================

* Allow claim mappings to be configured via admin.
* Allow group synchronization between role claims and Django groups.
* Allow added users to be promoted to staff users directly.
* Fixed missing INSTALLED_APP in the testproject.

0.3.0 (2021-07-19)
==================

* Add derivation of endpoints via OpenID Connect discovery endpoint
* Add fieldsets for OpenID Connect configuration admin page

0.2.1 (2021-07-06)
==================

* Fix variable name ``MOZILLA_DJANGO_OIDC_DB_CACHE_TIMEOUT`` to be the same as in the README

0.2.0 (2021-07-06)
==================

* Initial release
