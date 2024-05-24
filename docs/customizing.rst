=====================
Customizing behaviour
=====================

The default behaviour of mozilla-django-oidc-db (which is an extension on top of
mozilla-django-oidc, the upstream library) provides OpenID Connect configuration
to authenticate Django (admin) users. The default claim mapping and settings gravitate
towards staff users.

However, the generic mechanism of using database-backend configuration for one or more
OpenID Connect identity providers can be used much more broadly, and it doesn't even
have to manage Django user instances at all.

We offer flexibility through a generic configuration mechanism.

.. versionadded:: 0.17.0
    The generic configuration mechanism was added.


Models
======

We provide an abstract base model :class:`~mozilla_django_oidc_db.models.OpenIDConnectConfigBase`.

This makes some of the upstream library settings dynamic rather than having to specify
them as Django settings. Our :class:`~mozilla_django_oidc_db.models.OpenIDConnectConfig`
model is a concrete model based on it, which provides some additional configuration
aspects, such as claim mapping, specifying the username claim...

If you want to bring your own configuration, we recommend to subclass
:class:`~mozilla_django_oidc_db.models.OpenIDConnectConfigBase` in a similar way. You
can then define model fields or properties on your own model that correspond to the
lowercased setting name, for example:

.. code-block:: python

    from mozilla_django_oidc_db.fields import ClaimField
    from mozilla_django_oidc_db.models import (
        OpenIDConnectConfigBase,
        UserInformationClaimsSources,
    )


    class CustomConfig(OpenIDConnectConfigBase):
        oidcdb_username_claim = ClaimField(
            verbose_name=_("username claim"),
            default=get_default_username_claim,
            help_text=_("The name of the OIDC claim that is used as the username"),
        )

        @property
        def oidcdb_userinfo_claims_source(self):
            return UserInformationClaimsSources.id_token


For different purposes/flows, you can set up different configuration models.

.. note:: In the future, we will likely change from configuration classes/models to
   a single model with multiple instances, each holding their specific configuration
   values.


OIDC flow initialization
========================

Typically when a user needs to authenticate, they click a button or link to do so. This
navigation is tied to a particular URL path, for example ``/auth/oidc-custom/``.

We provide :class:`~mozilla_django_oidc_db.views.OIDCInit` to point the user to a
particular configuration. With the custom model from above:

.. code-block:: python
    :caption: myapp/urls.py

    from django.urls import path

    from mozilla_django_oidc_db.views import OIDCInit

    from myapp.models import CustomConfig


    urlpatterns = [
        ...,
        path(
            "auth/oidc-custom/",
            OIDCInit.as_view(config_class=CustomConfig, allow_next_from_query=True),
        ),
        ...,
    ]

This ensures that whenever a user authenticates via the ``/auth/oidc-custom/`` URL that
throughout the whole process your custom configuration will be used.

You can also subclass this view to modify the behaviour, optionally making it the
default via the ``OIDC_AUTHENTICATE_CLASS`` setting.

Recommended override hooks
--------------------------

:meth:`mozilla_django_oidc_db.views.OIDCInit.check_idp_availability`
    You can implement your own behaviour here to determine if the identity provider is
    available, before the user is redirected to the authentication endpoint.

Authentication backend(s)
=========================

The authentication backend :class:`~mozilla_django_oidc_db.backends.OIDCAuthenticationBackend`
automatically picks up the configuration specified by the initialization view. Out of
box, this will either create or update a django user with the user model specified from
your settings (unless ``OIDC_CREATE_USER`` is set to ``False``).

If you want real Django users to be managed, you don't need to do anything.

However, if you want to do more advanced stuff (like only storing certain claims in the
django session), you can subclass our backend to modify the behaviour. Don't forget
to add this backend to the ``AUTHENTICATION_BACKENDS`` setting.

Recommended override hooks
--------------------------

:meth:`mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_or_create_user`
    Override this method if you only want to extract some information and persist it
    somewhere else.

    You can return an :class:`~django.contrib.auth.models.AnonymousUser` instance to
    signal successful authentication.

:meth:`mozilla_django_oidc_db.backends.OIDCAuthenticationBackend._check_candidate_backend`
    Based on ``self.config_class``, you can determine if this backend is relevant for
    your authentication purposes. If you return ``False``, the backend will be skipped
    and the next one in ``AUTHENTICATION_BACKENDS`` will be tried.

    ``self.config_class`` will be the model specified in the init flow.


Callback flow
=============

:class:`~mozilla_django_oidc_db.views.OIDCCallbackView` takes care of preparing the
request for the authentication backend(s). Then, it grabs the callback view to apply
from the selected config model (by default this is
:class:`~mozilla_django_oidc_db.views.OIDCAuthenticationCallbackView`, making the
settings dynamic).

You can provide your own callback view handler and override behaviour. We recommend
you use :class:`~mozilla_django_oidc_db.views.OIDCAuthenticationCallbackView` as a
base. You can override any of the methods in
:class:`mozilla_django_oidc.views.OIDCAuthenticationCallbackView` of the upstream
library.

Finally, you must point to this view by overriding the :meth:`~mozilla_django_oidc_db.models.OpenIDConnectConfigBase.get_callback_view`
model method.

For example:

.. code-block:: python

    # views.py
    from mozilla_django_oidc_db.views import OIDCAuthenticationCallbackView


    class CustomCallbackView(OIDCAuthenticationCallbackView):
        @property
        def success_url(self):
            return "/custom-success-url"


    custom_callback_view = CustomCallbackView.as_view()


    # models.py

    class CustomCallbackViewConfig(OpenIDConnectConfigBase):
        ...

        def get_callback_view(self):
            from .views import custom_callback_view

            return custom_callback_view
