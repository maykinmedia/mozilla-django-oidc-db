from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.test import override_settings

import pytest

from mozilla_django_oidc_db.fields import EncryptedCharField


@pytest.mark.django_db
def test_secret_round_trips_correctly(dummy_config):
    """A value written through EncryptedCharField is returned identically on read."""
    from mozilla_django_oidc_db.models import OIDCClient

    original_secret = "super-secret-client-secret-value"
    dummy_config.oidc_rp_client_secret = original_secret
    dummy_config.save(update_fields=["oidc_rp_client_secret"])

    refreshed = OIDCClient.objects.get(pk=dummy_config.pk)
    assert refreshed.oidc_rp_client_secret == original_secret


@pytest.mark.django_db
def test_secret_not_stored_as_plaintext(dummy_config):
    """The raw DB value must not equal the plaintext secret."""
    secret = "my-plaintext-secret"
    dummy_config.oidc_rp_client_secret = secret
    dummy_config.save(update_fields=["oidc_rp_client_secret"])

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT oidc_rp_client_secret FROM mozilla_django_oidc_db_oidcclient WHERE id = %s",
            [dummy_config.pk],
        )
        raw_value = cursor.fetchone()[0]

    assert raw_value != secret, "Secret must not be stored in plaintext"
    assert secret not in raw_value, "Plaintext must not appear inside the stored value"


@pytest.mark.django_db
def test_missing_encryption_key_raises(dummy_config):
    """EncryptedCharField raises ImproperlyConfigured when the key is absent."""
    field = EncryptedCharField()

    with override_settings(OIDC_DB_ENCRYPTION_KEY=None):
        with pytest.raises(ImproperlyConfigured, match="OIDC_DB_ENCRYPTION_KEY"):
            field.get_prep_value("some-value")


@pytest.mark.django_db
def test_empty_value_passthrough(dummy_config):
    """Empty string and None values bypass encryption without errors."""
    field = EncryptedCharField()
    assert field.get_prep_value("") == ""
    assert field.get_prep_value(None) is None


@pytest.mark.django_db
def test_legacy_plaintext_returned_as_is(dummy_config):
    """
    Values written before encryption was introduced (plain text in DB) are
    returned as-is instead of raising an error, enabling gradual migration.
    """
    legacy_plaintext = "old-unencrypted-secret"

    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE mozilla_django_oidc_db_oidcclient SET oidc_rp_client_secret = %s WHERE id = %s",
            [legacy_plaintext, dummy_config.pk],
        )

    from mozilla_django_oidc_db.models import OIDCClient

    refreshed = OIDCClient.objects.get(pk=dummy_config.pk)
    # The fallback returns the raw value so existing deployments don't break.
    assert refreshed.oidc_rp_client_secret == legacy_plaintext
