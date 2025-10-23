from collections.abc import Sequence
from contextlib import nullcontext
from typing import TypedDict

from glom import assign
from pyquery import PyQuery as pq
from requests import Session

from mozilla_django_oidc_db.models import (
    OIDCClient,
    OIDCProvider,
    UserInformationClaimsSources,
)
from mozilla_django_oidc_db.typing import JSONObject


def keycloak_login(
    login_url: str,
    username: str = "testuser",
    password: str = "testuser",
    session: Session | None = None,
) -> str:
    """
    Test helper to perform a keycloak login.

    :param login_url: A login URL for keycloak with all query string parameters. E.g.
        `client.get(reverse("login"))["Location"]`.
    :returns: The redirect URI to consume in the django application, with the ``code``
        ``state`` query parameters. Consume this with ``response = client.get(url)``.
    """
    cm = Session() if session is None else nullcontext(session)
    with cm as session:
        login_page = session.get(login_url)
        assert login_page.status_code == 200

        # process keycloak's login form and submit the username + password to
        # authenticate
        document = pq(login_page.text)
        login_form = document("form#kc-form-login")
        submit_url = login_form.attr("action")
        assert isinstance(submit_url, str)
        login_response = session.post(
            submit_url,
            data={
                "username": username,
                "password": password,
                "credentialId": "",
                "login": "Sign In",
            },
            allow_redirects=False,
        )

        assert login_response.status_code == 302
        assert (redirect_uri := login_response.headers["Location"]).startswith(
            "http://testserver/"
        )

        return redirect_uri


class OIDCConfigOptions(TypedDict, total=False):
    """
    Provider and/or client configuration options, which map to model fields.
    """

    # provider fields
    oidc_op_discovery_endpoint: str
    oidc_op_jwks_endpoint: str
    oidc_op_authorization_endpoint: str
    oidc_op_token_endpoint: str
    oidc_op_user_endpoint: str
    oidc_op_logout_endpoint: str
    oidc_token_use_basic_auth: bool
    oidc_use_nonce: bool
    oidc_nonce_size: int
    oidc_state_size: int
    # client fields
    enabled: bool
    oidc_rp_client_id: str
    oidc_rp_client_secret: str
    oidc_rp_scopes_list: Sequence[str]
    oidc_rp_sign_algo: str
    oidc_rp_idp_sign_key: str
    oidc_keycloak_idp_hint: str
    userinfo_claims_source: UserInformationClaimsSources
    check_op_availability: bool
    options: JSONObject
    extra_options: JSONObject


def create_or_update_configuration(
    identifier_provider: str, identifier_config: str, data: OIDCConfigOptions
) -> OIDCClient:
    """Create or update a OIDCClient and OIDCProvider.

    The fields for the OIDCProvider are extracted from data and used to create/update
    the provider configuration. Then the fields for the OIDCClient are extracted and
    used to create/update the configuration. The foreign key to the provider will point
    to the just created/updated provider.

    It is possible to provide an extra field in the ``data`` dict called
    ``extra_options``. This is a dict with as key a dotted path for within the
    ``options`` field of the configuration, and as value the value to use for the
    specified field. For example, if ``extra_options`` is
    ``{"user_settings.claim_mappings.username": ["sub", "blob"]}``, then the
    configuration will have an options field:

    .. code:: python

       {
            "user_settings": {
                "claim_mappings": {
                    "username": ["sub", "blob"]
                }
            }
       }


    """

    oidc_provider_fields = [field.name for field in OIDCProvider._meta.fields]
    fields_provider = {
        key: value for key, value in data.items() if key in oidc_provider_fields
    }
    oidc_provider, _ = OIDCProvider.objects.update_or_create(
        identifier=identifier_provider,
        defaults=fields_provider,
    )

    oidc_config_fields = [field.name for field in OIDCClient._meta.fields]
    fields_config = {
        key: value for key, value in data.items() if key in oidc_config_fields
    }
    config, _ = OIDCClient.objects.update_or_create(
        identifier=identifier_config,
        defaults=fields_config,
    )
    config.oidc_provider = oidc_provider
    extra_options = data.get("extra_options")
    if extra_options:
        for path, value in extra_options.items():
            assign(config.options, path, value)
    config.save()

    return config
