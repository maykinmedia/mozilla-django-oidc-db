.. mozilla_django_oidc_db documentation master file, created by startproject.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to mozilla-django-oidc-db's documentation!
==================================================

|build-status| |ruff| |coverage|

|python-versions| |django-versions| |pypi-version|

Database-backed settings for mozilla-django-oidc, with modified unique identifiers for users

Features
========

* Thin layer on top of `mozilla-django-oidc`_
* Allows configuring OpenID connect providers and clients.
* Overrides `mozilla-django-oidc`_ default behaviour, using the ``sub`` claim
  instead of the ``email`` claim as unique identifier for users

``mozilla-django-oidc-db`` provides database configuration for several configuration
variables required for ``mozilla-django-oidc``, moving them from deploy-time to run-time.
This enables modification of the configuration, without having to restart the application.

Additionally, ``mozilla-django-oidc-db`` by default uses the ``sub`` (subject) claim
instead of the ``email`` claim as the unique identifier for users in the RP (Relying Party) application.
Using ``email`` as the unique identifier is not recommended, as mentioned in the `OpenID Connect specification`_.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   customizing
   setup_configuration
   reference
   architecture
   developers
   changelog



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. |build-status| image:: https://github.com/maykinmedia/mozilla-django-oidc-db/actions/workflows/ci.yml/badge.svg
    :target: https://github.com/maykinmedia/mozilla-django-oidc-db/actions/workflows/ci.yml

.. |ruff| image:: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json
    :target: https://github.com/astral-sh/ruff
    :alt: Ruff

.. |coverage| image:: https://codecov.io/gh/maykinmedia/mozilla-django-oidc-db/branch/master/graph/badge.svg
    :target: https://app.codecov.io/gh/maykinmedia/mozilla-django-oidc-db
    :alt: Coverage status

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/mozilla_django_oidc_db.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/mozilla_django_oidc_db.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/mozilla_django_oidc_db.svg
    :target: https://pypi.org/project/mozilla_django_oidc_db/

.. _mozilla-django-oidc: https://github.com/mozilla/mozilla-django-oidc

.. _OpenID Connect specification: https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
