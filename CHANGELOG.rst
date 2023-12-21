=========
Changelog
=========

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

* [`#51`_] Use defaults from SessionRefresh if variable not provided (`830945`_)

**Project maintenance/refactors**

* [`#48`_] Document claim obfuscation in README (`a753c7`_)


.. _830945: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/830945f64393d867cad61dbd4d130848d9dc2e0a
.. _a753c7: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/a753c765fb6732edd12e8fd87ae54597a2b40a84
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
* Customizable SoloModel cache prefix via CachingMixin (`7b0406`_)
* Add views to properly handle admin login failure (#33, `40be1f`_)

**Project maintenance/refactors**

* Define generic base class for OIDC config fields (`d12bdc`_)
* Removed unused Travis CI config
* Explicitly return None for empty values from config
* Added typehints

.. _d12bdc: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/d12bdcb6a9fcae8279e0696a808c1e52ad4cb7fd
.. _7b0406: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/7b0406101493f35f411508a0b028906ba4d47584
.. _40be1f: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/40be1f535a593197451d6b4e0ae5c13fe07aa3c0

0.8.0 (2022-02-15)
==================

* Allow usage of other config classes in SoloConfigMixin (`3f9c1d`_)

.. _3f9c1d: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/3f9c1d0ebc7c09df04c6e76406359da11fe84f7a

0.7.2 (2022-01-11)
==================

* Fix caching issues caused by `OpenIDConnectConfig.get_solo` in backend initialization (`ebb67c`_)
* Rename imported `SessionRefresh` in middleware to avoid conflicting names (`a6c4f6`_)

.. _ebb67c: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/ebb67cbdc4ede69d8e5e81c44626b29fe2dbb092
.. _a6c4f6: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/a6c4f6a78111f876549f55e38c3b197849cda4ef

0.7.1 (2021-11-29)
==================

* Fix verbose_name/help_text in username_claim migration (`d888d8`_)

.. _d888d8: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/a6c4f6a78111f876549f55e38c3b197849cda4ef

0.7.0 (2021-11-29) **YANKED**
=============================

* Add configurable username claim (defaults to ``sub``) (`ea07b3`_)

.. _ea07b3: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/ea07b3cbb687b3b0ddf738731686fceb930e3c76

0.6.0 (2021-11-26)
==================

* Add configurable glob pattern for groups sync, to only sync groups that match the pattern (`f325fe`_)
* Fix OIDC config form for users with readonly access (`99aeb4`_)

.. _f325fe: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/f325feea4f10e86c1e69979026b523c6ce68d20c
.. _99aeb4: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/99aeb4eb6d7ee8d21fe0c7edb93d62af38658a0e

0.5.0 (2021-09-13)
==================

* Pin mozilla-django-oidc to >=1.0.0, <2.0.0 (due to compatibility issues) (`f50408`_)
* Adapt admin form to allow configurable endpoints that must be derived from discovery endpoint (`07203f`_)

.. _f50408: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/f50408e7e94b2e95f6d1e2c122bb693b1e8d91f8
.. _07203f: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/07203f9fb42004fe2e351980953a3f774d07a442

0.4.0 (2021-08-16)
==================

* Allow claim mappings to be configured via admin.
* Allow group synchronization between role claims and Django groups.
* Allow added users to be promoted to staff users directly.
* Fixed missing INSTALLED_APP in the testproject.

0.3.0 (2021-07-19)
==================

* Add derivation of endpoints via OpenID Connect discovery endpoint (`029c6e`_)
* Add fieldsets for OpenID Connect configuration admin page (`18aae5`_)

.. _029c6e: https://github.com/maykinmedia/mozilla-django-oidc-db/commit/029c6efe561c9024b716ea9316fde4f81c0ec3d0
.. _18aae5 : https://github.com/maykinmedia/mozilla-django-oidc-db/commit/18aae53fed05157874949e15dabeda42af0ebc48

0.2.1 (2021-07-06)
==================

* Fix variable name ``MOZILLA_DJANGO_OIDC_DB_CACHE_TIMEOUT`` to be the same as in the README

0.2.0 (2021-07-06)
==================

* Initial release
