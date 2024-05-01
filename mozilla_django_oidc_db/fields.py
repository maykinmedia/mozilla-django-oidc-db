from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField


class ClaimField(ArrayField):
    """
    A field to store a path to claims holding the desired value(s).

    Each item is a segment in the path from the root to leaf for nested claims.
    """

    def __init__(self, *args, **kwargs):
        kwargs["base_field"] = models.CharField(_("claim path segment"), max_length=50)
        super().__init__(*args, **kwargs)
