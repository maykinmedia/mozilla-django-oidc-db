.. _developers:

=============
Running tests
=============

Tox
===

To run the tests with Tox locally, you need to create a user in postgres with ``CREATEDB`` rights.
Then, you need to set the following environment variables:

* ``PGUSER``
* ``PGDATABASE``
* ``PGPASSWORD``
* ``PGPORT``
* ``PGHOST``

==================
Running dev server
==================

In the root of the repository, run:

.. code:: bash

    export DJANGO_SETTINGS_MODULE=testapp.settings
    export PYTHONPATH=$PYTHONPATH:`pwd`

You need to have postgres setup with a database, you can look at ``testapp/settings.py`` to see the default
credentials used to connect to the database.

Then, you can run:

.. code:: bash

    django-admin migrate
    django-admin runserver