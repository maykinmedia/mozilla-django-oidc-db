.. _customizing:

=====================
Customizing behaviour
=====================

The default behaviour of mozilla-django-oidc-db (which is an extension on top of
mozilla-django-oidc, the upstream library) provides OpenID Connect configuration
to authenticate Django (admin) users. The default claim mapping and settings gravitate
towards staff users.

However, the generic mechanism of using a database-backed configuration for one or more
OpenID Connect identity providers can be used much more broadly, and it doesn't even
have to manage Django user instances at all.

We offer flexibility through a generic configuration mechanism.

.. versionadded:: 0.17.0
    The generic configuration mechanism was added.

.. versionadded:: 0.24.0
    The models were refactored to no longer be solo-models.


Models
======

We provide a model :class:`~mozilla_django_oidc_db.models.OIDCClient`.

This makes some of the upstream library settings dynamic rather than having to specify
them as Django settings. The :class:`~mozilla_django_oidc_db.models.OIDCClient` has a JSON field ``options`` that can be used
to specify any configuration that is specific to an OIDC Identity Provider.
The structure of this field is specified with a JSON schema and thanks to ``django-jsonform`` the admin displays a nice
form for it instead of a plain text field.

If you want to bring your own configuration, you should create a new :class:`~mozilla_django_oidc_db.models.OIDCClient`
and a corresponding plugin that should implement the interface specified by either the 
:class:`~mozilla_django_oidc_db.plugins.AnonymousUserOIDCPluginProtocol` or the :class:`~mozilla_django_oidc_db.plugins.AbstractUserOIDCPluginProtocol`.
The plugin should be registered with the same identifier as the corresponding :class:`~mozilla_django_oidc_db.models.OIDCClient`.
You can inherit from the :class:`~mozilla_django_oidc_db.plugins.BaseOIDCPlugin` to inherit some
of the base plugin behaviour.


Plugin
======

We use a plugin architecture to encapsulate any behaviour specific to a particular OIDC provider or Identity Provider.

A custom plugin can be registered as follows:

.. code-block:: python

    from mozilla_django_oidc_db.registry import register

    @register("oidc-custom-identifier")
    class OIDCCustomPlugin(AbstractUserOIDCPluginProtocol):
        ...

The protocol :class:`~mozilla_django_oidc_db.plugins.OIDCBasePluginProtocol` specifies the functionality that all plugins
should implement, while the :class:`~mozilla_django_oidc_db.plugins.AnonymousUserOIDCPluginProtocol` and 
:class:`~mozilla_django_oidc_db.plugins.AbstractUserOIDCPluginProtocol` specify additional methods that should be implemented 
depending on whether Django users should be created when a user logs in with OIDC or not.

At start-up, a signal will run after the migrations to create an ``OIDCClient`` (if it doesn't already exist) for every plugin
registered.

The :class:`~mozilla_django_oidc_db.views.OIDCCallbackView` and the :class:`~mozilla_django_oidc_db.backends.OIDCAuthenticationBackend`
both rely on the plugins. This should make it possible to implement all custom behaviour in the plugins without 
having to override the callback view and the backend.


OIDC flow initialization
========================

Typically when a user needs to authenticate, they click a button or link to do so. This
navigation is tied to a particular URL path, for example ``/auth/oidc-custom/``.

We provide :class:`~mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView` to start an OIDC authentication flow.
This view class is parametrized with the identifier of the config model, so that
the specific configuration can be retrieved and settings such as the identity provider endpoint
to redirect the user to can be obtained.

This view is not necessarily meant to be exposed directly via a URL pattern, but
rather specific views are to be created from it, e.g.:

.. code-block:: python

    from mozilla_django_oidc_db.views import OIDCAuthenticationRequestInitView

    digid_init = OIDCAuthenticationRequestInitView.as_view(identifier="digid-oidc")
    redirect_response = digid_init(request) # Redirect to some keycloak instance, for example.

An example of a pre-configured view to use as the "default" could be as follows:

.. code-block:: python

    from mozilla_django_oidc_db.constants import OIDC_ADMIN_CONFIG_IDENTIFIER

    class OIDCDefaultAuthenticationRequestView(OIDCAuthenticationRequestInitView):
        identifier = OIDC_ADMIN_CONFIG_IDENTIFIER
        allow_next_from_query = True

And then by configuring ``OIDC_AUTHENTICATE_CLASS`` to point to this class would result in this view being 
used as default.


Recommended override hooks
--------------------------

.. todo:: Should this maybe be moved to the plugin? 

:meth:`mozilla_django_oidc_db.views.OIDCAuthenticationRequestInitView.check_idp_availability`
    You can implement your own behaviour here to determine if the identity provider is
    available, before the user is redirected to the authentication endpoint.

Authentication backend(s)
=========================

The authentication backend :class:`~mozilla_django_oidc_db.backends.OIDCAuthenticationBackend`
retrieves the ``OIDCClient`` whose identifier has been stored on the request session by the initialization view. 

If you want real Django users to be managed, you don't need to do anything.

However, if you want to do more advanced stuff (like only storing certain claims in the
django session), you can subclass our backend to modify the behaviour. Don't forget
to add this backend to the ``AUTHENTICATION_BACKENDS`` setting.



Callback flow
=============

:class:`~mozilla_django_oidc_db.views.OIDCCallbackView` takes care of preparing the
request for the authentication backend(s). It stores the ``OIDCClient`` in the ``request._oidcdb_config``
Based on the identifier of the ``OIDCClient``, :class:`~mozilla_django_oidc_db.views.OIDCCallbackView` calls the 
method ``handle_callback`` of the corresponding plugin. This method should then call the appropriate callback view to use.
For example, this could be:

.. code-block:: python

    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        return default_callback_view(request)

Where:

.. code-block:: python

    from mozilla_django_oidc_db.views import OIDCAuthenticationCallbackView

    default_callback_view = OIDCAuthenticationCallbackView.as_view()


You can implement your own callback view. We recommend using :class:`~mozilla_django_oidc_db.views.OIDCAuthenticationCallbackView`
as a base.

From the ``get`` method in the callback view :class:`~mozilla_django_oidc.views.OIDCAuthenticationCallbackView`
the backend ``authenticate`` method will be called.

Templatetags
============

We provide a template tag to retrieve the admin :class:`~mozilla_django_oidc_db.models.OIDCClient` model.

This tag can be used as follows:

.. code-block:: jinja

    {% load mozilla_django_oidc_db %}

    {% get_oidc_admin_client as oidc_config %}
    {% if oidc_config.enabled %}
        <div>Some special text if logging into the admin with OIDC is enabled.</div>
    {% endif %}

