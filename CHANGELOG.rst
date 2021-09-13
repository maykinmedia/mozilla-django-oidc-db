=========
Changelog
=========

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
