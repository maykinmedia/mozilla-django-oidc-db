=========
Changelog
=========

0.17.0 (2024-05-??)
===================

Refactor/rewrite release.

The custom views and backend have been rewritten to be more configurable out of the box,
without needing to write much code in your own project. We've incorporated our
experiences from the Open Forms and Open Inwoner projects in this rewrite.

**💥 Breaking changes**

While we were able to perform most of the changes without breaking public API, some
aspects could not be avoided.

* The attributes ``OIDCAuthenticationBackend.sensitive_claim_names`` and
  ``OIDCAuthenticationBackend.config_identifier_field`` are removed. This affects you
  if you were subclassing this backend to override these attributes.

  You can provide these in your custom configuration model(s) as the
  ``oidcdb_sensitive_claims`` and ``oidcdb_username_claim`` model fields or properties.
  See the implementation of the ``OpenIDConnectConfigBase`` model for more details.

* ``mozilla_django_oidc_db.models.CachingMixin`` is removed. Our base model overrides the
  generated cache key so that it uniquely points to a specific Django model.

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
