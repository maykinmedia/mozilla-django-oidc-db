from urllib.parse import parse_qs, urlparse

from django.contrib.sessions.middleware import SessionMiddleware
from django.http.response import HttpResponseRedirect
from django.test import RequestFactory
from django.urls import reverse

import pytest

from mozilla_django_oidc_db.constants import CONFIG_CLASS_SESSION_KEY
from mozilla_django_oidc_db.middleware import SessionRefresh
from mozilla_django_oidc_db.models import OpenIDConnectConfig, OpenIDConnectConfigBase
from testapp.models import AnotherEmptyConfig, EmptyConfig


@pytest.fixture(scope="session")
def dummy_view():
    def get_response(*args, **kwargs):
        pass

    return get_response


@pytest.fixture(scope="session")
def session_middleware(dummy_view):
    return SessionMiddleware(dummy_view)


@pytest.fixture(scope="session")
def session_refresh(dummy_view):
    return SessionRefresh(dummy_view)


@pytest.fixture()
def request_factory(rf: RequestFactory, session_middleware):
    def _factory(
        config_class: type[OpenIDConnectConfigBase] | None = None, *, path: str = ""
    ):
        request = rf.get(path or "/")
        session_middleware(request)
        session = request.session
        session[CONFIG_CLASS_SESSION_KEY] = (
            config_class or OpenIDConnectConfig
        )._meta.label
        session.save()
        return request

    return _factory


@pytest.fixture()
def config_factory(db):
    def _factory(cls: type[OpenIDConnectConfigBase], /, **overrides):
        BASE = f"https://mock-oidc-provider-{cls._meta.model_name}:9999"

        config, _ = cls.objects.update_or_create(
            pk=cls.singleton_instance_id,
            defaults={
                "enabled": True,
                "oidc_rp_client_id": "fake",
                "oidc_rp_client_secret": "even-faker",
                "oidc_rp_sign_algo": "RS256",
                "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
                "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
                "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
                "oidc_op_token_endpoint": f"{BASE}/oidc/token",
                "oidc_op_user_endpoint": f"{BASE}/oidc/user",
                **overrides,
            },
        )
        # in case caching is setup, ensure that it is invalidated
        config.save()

        return config

    return _factory


@pytest.mark.oidcconfig(enabled=False)
def test_sessionrefresh_oidc_not_enabled(
    dummy_config: OpenIDConnectConfig,
    request_factory,
    session_refresh: SessionRefresh,
):
    request = request_factory(dummy_config)

    # Running the middleware should return None, since OIDC is disabled
    result = session_refresh(request)

    assert result is None


@pytest.mark.oidcconfig(
    enabled=True,
    oidc_rp_client_id="initial-client-id",
    oidc_rp_scopes_list=["openid", "email"],
)
def test_sessionrefresh_config_always_refreshed(
    dummy_config: OpenIDConnectConfig,
    request_factory,
    session_refresh: SessionRefresh,
    mocker,
):
    """
    Middleware should refresh the config on every call
    """
    mocker.patch.object(session_refresh, "is_refreshable_url", return_value=True)
    request = request_factory()

    result1 = session_refresh(request)
    assert isinstance(result1, HttpResponseRedirect)
    query1 = parse_qs(urlparse(result1.url).query)
    assert query1["client_id"] == ["initial-client-id"]
    assert query1["scope"] == ["openid email"]

    dummy_config.oidc_rp_client_id = "some-other-id"
    dummy_config.oidc_rp_scopes_list = ["openid", "email", "other_scope"]  # type: ignore
    dummy_config.save()

    result2 = session_refresh(request)
    assert isinstance(result2, HttpResponseRedirect)
    query2 = parse_qs(urlparse(result2.url).query)
    assert query2["client_id"] == ["some-other-id"]
    assert query2["scope"] == ["openid email other_scope"]


@pytest.mark.oidcconfig(enabled=True)
def test_sessionrefresh_config_use_defaults(
    dummy_config,
    settings,
    session_refresh: SessionRefresh,
    request_factory,
    mocker,
):
    """
    Middleware should respect fallbacks to settings/defaults.
    """
    settings.OIDC_AUTHENTICATION_CALLBACK_URL = "admin:index"
    mocker.patch.object(session_refresh, "is_refreshable_url", return_value=True)

    request = request_factory(dummy_config.__class__)

    result = session_refresh(request)

    assert isinstance(result, HttpResponseRedirect)
    query = parse_qs(urlparse(result.url).query)
    assert query["redirect_uri"] == ["http://testserver/admin/"]
    assert len(query["nonce"][0]) == 32  # default set on middleware dynamic_setting


@pytest.mark.django_db
@pytest.mark.parametrize(
    "config_cls",
    (
        EmptyConfig,
        AnotherEmptyConfig,
    ),
)
def test_sessionfresh_selects_correct_backend_based_on_session_parameters(
    config_cls,
    config_factory,
    request_factory,
    session_refresh: SessionRefresh,
    mocker,
):
    config_factory(EmptyConfig, enabled=True, oidc_rp_client_id="empty-config")
    config_factory(
        AnotherEmptyConfig, enabled=True, oidc_rp_client_id="another-empty-config"
    )
    mocker.patch.object(session_refresh, "is_refreshable_url", return_value=True)
    request = request_factory(config_cls)

    result1 = session_refresh(request)
    assert isinstance(result1, HttpResponseRedirect)
    assert (
        f"https://mock-oidc-provider-{config_cls._meta.model_name}"
        in result1["Location"]
    )
    query1 = parse_qs(urlparse(result1.url).query)
    assert query1["client_id"] == [config_cls.get_solo().oidc_rp_client_id]


@pytest.mark.django_db
@pytest.mark.parametrize(
    "config_cls",
    (
        EmptyConfig,
        AnotherEmptyConfig,
    ),
)
def test_sessionfresh_adds_config_specific_callback_url_to_exempt_urls(
    config_cls,
    config_factory,
    request_factory,
    session_refresh: SessionRefresh,
    mocker,
):
    class MockUser:
        @property
        def is_authenticated(self):
            return True

    config_factory(EmptyConfig, enabled=True)
    config_factory(AnotherEmptyConfig, enabled=True)
    callback_url = reverse(config_cls.get_solo().oidc_authentication_callback_url)

    request = request_factory(config_cls, path=callback_url)
    request.user = MockUser()
    session_refresh._set_config_from_request(request)

    assert callback_url in session_refresh.exempt_urls
    assert session_refresh.is_refreshable_url(request) is False


@pytest.mark.django_db
def test_sessionfresh_does_nothing_for_non_oidc_requests(
    rf,
    session_refresh: SessionRefresh,
    mocker,
):
    mocker.patch.object(session_refresh, "is_refreshable_url", return_value=True)
    request = rf.get("/")

    result = session_refresh(request)

    assert result is None
