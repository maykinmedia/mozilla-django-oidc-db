=========
Changelog
=========

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
