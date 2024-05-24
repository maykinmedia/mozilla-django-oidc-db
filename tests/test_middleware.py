from urllib.parse import parse_qs, urlparse

from django.contrib.sessions.middleware import SessionMiddleware
from django.http.response import HttpResponseRedirect
from django.test import RequestFactory

import pytest

from mozilla_django_oidc_db.middleware import SessionRefresh
from mozilla_django_oidc_db.models import OpenIDConnectConfig


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


@pytest.mark.oidcconfig(enabled=False)
def test_sessionrefresh_oidc_not_enabled(
    dummy_config: OpenIDConnectConfig,
    rf: RequestFactory,
    session_refresh: SessionRefresh,
):
    request = rf.get("/")

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
    rf: RequestFactory,
    session_middleware: SessionMiddleware,
    session_refresh: SessionRefresh,
    mocker,
):
    """
    Middleware should refresh the config on every call
    """
    mocker.patch.object(session_refresh, "is_refreshable_url", return_value=True)
    request = rf.get("/")
    session_middleware(request)

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
    session_middleware: SessionMiddleware,
    session_refresh: SessionRefresh,
    rf: RequestFactory,
    mocker,
):
    """
    Middleware should respect fallbacks to settings/defaults.
    """
    settings.OIDC_AUTHENTICATION_CALLBACK_URL = "admin:index"
    mocker.patch.object(session_refresh, "is_refreshable_url", return_value=True)

    request = rf.get("/")
    session_middleware(request)

    result = session_refresh(request)

    assert isinstance(result, HttpResponseRedirect)
    query = parse_qs(urlparse(result.url).query)
    assert query["redirect_uri"] == ["http://testserver/admin/"]
    assert len(query["nonce"][0]) == 32  # default set on middleware dynamic_setting


def test_attributeerror_for_non_oidc_attribute(
    dummy_config, session_refresh: SessionRefresh
):
    with pytest.raises(AttributeError):
        session_refresh.__name__  # type: ignore

    # OIDC attributes should never raise AttributeErrors
    assert session_refresh.OIDC_AUTHENTICATION_CALLBACK_URL
