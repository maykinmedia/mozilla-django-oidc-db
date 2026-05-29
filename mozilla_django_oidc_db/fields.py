from django.conf import settings
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

    Encryption is **opt-in**: if ``settings.OIDC_DB_ENCRYPTION_KEY`` is not set
    the field behaves exactly like a plain ``TextField`` so that existing
    deployments continue to work without any changes.  Set the key to start
    encrypting new writes; existing plaintext rows are returned as-is and will be
    silently re-encrypted on the next save.

    To generate a key::

        from cryptography.fernet import Fernet
        print(Fernet.generate_key().decode())

    Add the result to your Django settings as ``OIDC_DB_ENCRYPTION_KEY``.
    """

    def _get_fernet(self):
        """Return a Fernet instance if a key is configured, otherwise None."""
        key = getattr(settings, "OIDC_DB_ENCRYPTION_KEY", None)
        if not key:
            return None
        from cryptography.fernet import Fernet

        return Fernet(key)

    def get_prep_value(self, value: str | None) -> str | None:
        """Encrypt before writing to the database (no-op when key is absent)."""
        if not value:
            return value
        fernet = self._get_fernet()
        if fernet is None:
            return value
        return fernet.encrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection) -> str | None:
        """Decrypt after reading from the database (no-op when key is absent)."""
        if not value:
            return value
        fernet = self._get_fernet()
        if fernet is None:
            return value
        try:
            return fernet.decrypt(value.encode()).decode()
        except Exception:
            # Backward-compatibility: the value was stored as plaintext before
            # encryption was enabled.  Return as-is; it will be re-encrypted
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
