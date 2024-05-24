============
Architecture
============

The architecture of mozilla-django-oidc-db is so that you can bring your own
configuration classes/models and adapt the behaviour, while still encapsulating the
OpenID Connect protocol interaction. See :ref:`customizing` for how to do this.

The flow is captured in the ASCII art below.

.. code-block:: none

    +--------------+  +--------------+  +--------------+
    | init@ConfigA |  | init@ConfigB |  | init@ConfigC |
    +------+-------+  +-----+--------+  +------+-------+
           |                |                  |
           +----------------+------------------+
                            |
                            v
                     +------+------+
                     |  OIDCInit   |
                     +------+------+
                            |
                            v
                        +---+---+
                        |   OP  |
                        +---+---+
                            |
                            v
                +-----------+------------+
                |  Routing Callback View |
                +-----------+------------+
                            |
                            v
                +-----------+------------+
                |                        |
                v                        v
          +-----+------+            +----+-------+
          | Callback X |            | Callback Y |
          +-----+------+            +----+-------+
                |                        |
                +-----------+------------+
                            |
                            v
                      +-----+--------+
                      | Auth Backend |
                      +--------------+
                            |
                            v
                 +----------+-------------+
                 | Callback view redirect |
                 +------------------------+


The assumed configuration inheritance chain is:

.. code-block:: python

    class ConfigA(OpenIDConnectConfigBase):
        ...


    class ConfigB(OpenIDConnectConfigBase):
        ...


    class ConfigC(OpenIDConnectConfigBase):
        ...


That is - each config class has its own behaviours associated.

Flow
====

In this diagram, there are three OIDC init entrypoints, one for each configuration model.
They share the initialization logic (:class:`~mozilla_django_oidc_db.views.OIDCInit`),
which takes care of recording the desired configuration class to apply in the callback
flow.

Then, the user is redirected to the OpenID Provider, where they authenticate with their
credentials. On successful auth (or error situations), the user is redirected to the
callback endpoint, ending up in our ``Routing Callback View``. This looks up which
callback view function to apply, depending on the configuration specified during the
init flow.

Typically, as part of the callback view, the ``settings.AUTHENTICATION_BACKENDS`` will
be tried in order, which will hit (one of) our backends that completes the OpenID
Connect flow, yielding user information. This would typically result in a django user
being logged in and being redirected to the success (or failure) URL specified from
the callback.

Note that not every configuration class needs to provide their own callback view.
