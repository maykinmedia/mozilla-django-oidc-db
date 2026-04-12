from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField


@deconstructible
class ClaimFieldDefault:
    """
    Callable default for ClaimField.

    Django's ArrayField requires a callable to be passed for the ``default`` kwarg, to
    avoid sharing a mutable value shared by all instances. This custom class provides
    a straight-forward interface so that defaults can be provided inline rather than
    requiring a function to be defined at the module level, since lambda's cannot be
    serialized for migrations.

    Usage:

    >>> field = ClaimField(default=ClaimFieldDefault("foo", "bar"))
    >>> field.get_default()  # ["foo", "bar"]
    """

    def __init__(self, *bits: str):
        self.bits = list(bits)

    def __eq__(self, other) -> bool:
        if isinstance(other, ClaimFieldDefault):
            return self.bits == other.bits
        return False

    def __call__(self) -> list[str]:
        return self.bits

    def __hash__(self) -> int:
        return hash(tuple(self.bits))


class EncryptedCharField(models.TextField):
    """
    A field that transparently encrypts its value at rest using Fernet symmetric
    encryption (AES-128-CBC + HMAC-SHA256).

    Requires ``settings.OIDC_DB_ENCRYPTION_KEY`` to be set to a valid Fernet key
    (URL-safe base64-encoded 32 bytes).  Generate one with::

        from cryptography.fernet import Fernet
        print(Fernet.generate_key().decode())

    Existing plaintext values (written before this field was added) are returned
    as-is on first read so that existing deployments do not break.  They will be
    re-encrypted the next time the record is saved.
    """

    def _get_fernet(self):
        from cryptography.fernet import Fernet

        key = getattr(settings, "OIDC_DB_ENCRYPTION_KEY", None)
        if not key:
            raise ImproperlyConfigured(
                "OIDC_DB_ENCRYPTION_KEY must be set in Django settings to use "
                "EncryptedCharField.  Generate a key with: "
                "from cryptography.fernet import Fernet; Fernet.generate_key()"
            )
        return Fernet(key)

    def get_prep_value(self, value: str | None) -> str | None:
        """Encrypt before writing to the database."""
        if not value:
            return value
        fernet = self._get_fernet()
        return fernet.encrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection) -> str | None:
        """Decrypt after reading from the database."""
        if not value:
            return value
        fernet = self._get_fernet()
        try:
            return fernet.decrypt(value.encode()).decode()
        except Exception:
            # Backward-compatibility: the value was stored as plaintext before
            # this field was introduced.  Return as-is; it will be re-encrypted
            # on the next save.
            return value


class ClaimField(ArrayField):
    """
    A field to store a path to claims holding the desired value(s).

    Each item is a segment in the path from the root to leaf for nested claims.
    """

    def __init__(self, *args, **kwargs):
        kwargs["base_field"] = models.CharField(_("claim path segment"), max_length=50)
        super().__init__(*args, **kwargs)
