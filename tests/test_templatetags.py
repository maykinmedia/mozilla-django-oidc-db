import pytest

from mozilla_django_oidc_db.constants import OIDC_ADMIN_CONFIG_IDENTIFIER
from mozilla_django_oidc_db.models import OIDCClient
from mozilla_django_oidc_db.templatetags.mozilla_django_oidc_db import (
    get_oidc_admin_client,
)

from .conftest import oidcconfig


@oidcconfig(enabled=True)
def test_templatetag_admin_oidc_enabled(filled_admin_config):
    retrieved_client = get_oidc_admin_client()

    assert retrieved_client == filled_admin_config


@pytest.mark.django_db
def test_templatetag_admin_oidc_disabled():
    # The object is present because the migrations create it
    OIDCClient.objects.filter(identifier=OIDC_ADMIN_CONFIG_IDENTIFIER).delete()

    retrieved_client = get_oidc_admin_client()

    assert retrieved_client is None
