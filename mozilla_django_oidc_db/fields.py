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


class ClaimField(ArrayField):
    """
    A field to store a path to claims holding the desired value(s).

    Each item is a segment in the path from the root to leaf for nested claims.
    """

    def __init__(self, *args, **kwargs):
        kwargs["base_field"] = models.CharField(_("claim path segment"), max_length=50)
        super().__init__(*args, **kwargs)
