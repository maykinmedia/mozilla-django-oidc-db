============
Architecture
============

The architecture of mozilla-django-oidc-db is so that you can bring your own
configuration classes/models and adapt the behaviour, while still encapsulating the
OpenID Connect protocol interaction. See :ref:`customizing` for how to do this.

The flow is captured in the ASCII art below.

.. code-block:: none

    +-------------------------+  +-----------------------------------+
    | OIDC_AUTHENTICATE_CLASS |  | OIDCAuthenticationRequestInitView |
    +------+------------------+  +-------------+---------------------+
           |                                   |
           +----------------+------------------+
                            |
                            v
                        +---+---+
                        |   OP  |
                        +---+---+
                            |
                            v
                +-----------+--------------+
                | Routing OIDCCallbackView |
                +-----------+--------------+
                            |
                            v
                +-----------+--------------+
                | Plugin.handle_callback   |
                +-----------+--------------+
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


Flow
====

This diagram shows that it is possible to choose the authentication request view
either by setting the ``OIDC_AUTHENTICATE_CLASS`` variable, or by routing to a particular
authentication request init view (:class:`~mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView`) 
that can be specified as follows:

.. code:: python

    view_init = OIDCAuthenticationRequestInitView.as_view(identifier="some-identifier")

The initialisation view performs some extra logic compared to the parent 
:class:`~mozilla_django_oidc.views.OIDCAuthenticationRequestView`, like recording the ``identifier`` of 
the :class:`~mozilla_django_oidc_db.models.OIDCClient` in the session. 
This is needed, so that in the callback we know which OIDC plugin
should be used.

Then, the user is redirected to the OpenID Connect Provider, where they authenticate with their
credentials. On successful auth (or error situations), the user is redirected to the
callback endpoint configured with the variable ``OIDC_CALLBACK_CLASS`` (which should be set to our 
:class:`~mozilla_django_oidc_db.views.OIDCCallbackView`). This looks up which pluging
to use, depending on the ``identifier`` specified in the authentication request view.
The plugin will then handle the request by routing it to the appropriate :class:`~mozilla_django_oidc_db.views.OIDCAuthenticationCallbackView`.

Typically, as part of the callback view, the ``settings.AUTHENTICATION_BACKENDS`` will
be tried in order, which will hit the :class:`~mozilla_django_oidc_db.backends.OIDCAuthenticationBackend` backend
which completes the OpenID Connect flow, yielding user information. 

Depending on the plugin, this can result in a Django ``User`` being logged in and being redirected to 
the success (or failure) URL specified from the callback. Alternatively, an ``AnonymousUser`` is redirected to 
the success (or failure) URL specified from the callback.
